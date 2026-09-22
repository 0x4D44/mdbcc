//! S1b.4 — Module → coff::Object converter.
//!
//! Per HLD §1.2 / §2.4: takes the codegen-internal [`crate::codegen::Module`]
//! and produces a linker-facing [`crate::coff::Object`]. This is the new
//! pipeline seam — mdbcc's codegen still produces a Module today; the
//! converter here lowers that Module to the COFF Object IR that mdlink
//! (S1c) will consume.
//!
//! ## Mapping summary (HLD §2.4)
//!
//! Sections (only emitted when non-empty):
//! - `.text` — concatenated function code, padded to 16-byte boundaries
//!   between functions. Per-function EXTERNAL symbol (mangled name).
//! - `.data` — every `Module.globals[i]` (mdbcc does not split out a
//!   separate `.bss` today; zero-initialised globals also live in
//!   `.data` per the existing pe.rs convention). Per-global STATIC
//!   symbol.
//! - `.rdata` — string literals (deduped across the module), FP literals
//!   (already promoted to globals — these live in `.data`), vtables, and
//!   typeinfo entries. STATIC `.Lstr.*` / `.Lvtbl.*` / `.Lxt.*` symbols.
//! - `.pdata` / `.xdata` — only when at least one function carries
//!   `try_scopes`. The synthetic personality function emitted by
//!   `compile_module` (last `Module.funcs` entry when SEH is active)
//!   is referenced from each try-bearing function's UNWIND_INFO. We
//!   keep the existing in-tree personality function definition rather
//!   than treating it as an UNDEFINED EXTERNAL: this matches what
//!   pe.rs does today, gives lld-link a self-contained object, and
//!   sidesteps mdlink dependencies that don't exist yet.
//!
//! Relocations follow the table in HLD §2.4:
//! - `CallSite::callee` → `Rel32` against the function symbol.
//! - `RipRef::Import(name)` → `Rel32` against UNDEFINED EXTERNAL
//!   `__imp_<name>` (Q4 ratified convention).
//! - `RipRef::Str(idx)` → `Rel32` against the `.Lstr.*` static.
//! - `RipRef::Data(idx)` → `Rel32` against the global's symbol.
//! - `RipRef::Func(name)` → `Rel32` against the function symbol.
//! - `RipRef::Vtable(rec_id)` → `Rel32` against the `.Lvtbl.*` static.
//! - Vtable slot (absolute function address) → `Addr64` against the
//!   target function symbol.
//! - Typeinfo class/base RVA fields → `Addr32nb` against the target
//!   vtable static.
//! - `.pdata` RUNTIME_FUNCTION fields → `Addr32nb` against the function
//!   (Begin/End) and `.xdata` (UnwindInfoAddress) symbols.
//! - `.xdata` scope-table function/handler/typeinfo RVAs →
//!   `Addr32nb` against the function or `.Lxt.*` static.
//!
//! ## Determinism (R16 — hard)
//!
//! The converter emits sections, symbols, and relocations in deterministic
//! order. Module.funcs / Module.globals / Module.vtables /
//! Module.typeinfo are already Vec-ordered; iteration over them respects
//! insertion order. Cross-cutting symbol allocation (e.g. UNDEFINED
//! externals collected from CallSite::callee / RipRef::Import) is keyed
//! by name and walked through Vec-ordered structures, then sorted by
//! lexicographic name at the end of collection so the placement of
//! "first appearance" matters for grouping but the final ordering is
//! a pure function of the name set.

use std::collections::BTreeMap;

use crate::codegen::{CompiledFn, Module, RipRef};
use crate::coff::{
    AuxRecord, Object, Reloc, RelocKind, Section, SectionRef, StorageClass, SymKind, SymName,
    Symbol,
};
use crate::eh::{CatchPolicy, PERSONALITY_FN_NAME};

/// Convenience prefix for the per-string `.Lstr.*` static symbols. The
/// HLD allows either content-hashed or numeric forms; we pick numeric
/// (function-index + string-index) because it's deterministic, short,
/// and trivially readable in `dumpbin /symbols` output. Within `.rdata`
/// strings are deduped by content (matching what pe.rs does today via
/// `build_rdata`), so multiple `.Lstr.*` symbols may share an offset.
const STR_PREFIX: &str = ".Lstr";
const VTABLE_PREFIX: &str = ".Lvtbl";
const TYPEINFO_PREFIX: &str = ".Lxt";

/// 32-byte alignment between functions in `.text`. Per HLD §2 we aim
/// for 16-byte function alignment for future COMDAT readiness; the
/// padding is plain `0xCC` (int3 — traps if accidentally executed).
const FN_ALIGN: usize = 16;

impl Module {
    /// Convert this Module into a `coff::Object` suitable for linking
    /// per HLD §1.2 / §2.4.
    ///
    /// Pure converter: every input artefact (function, global, vtable,
    /// typeinfo entry, EH scope) maps to a COFF section + symbols +
    /// relocations. The output is byte-identical across runs given the
    /// same Module input — all internal iteration is over `Vec`s (R16).
    ///
    /// The personality function (the synthetic last `Module.funcs`
    /// entry when SEH is active) is treated as an ordinary defined
    /// function and emitted into `.text` like every other function.
    pub fn to_object(&self) -> Object {
        Converter::new(self).run()
    }
}

// ---------------------------------------------------------------------------
// Layout planning
// ---------------------------------------------------------------------------

/// Per-function placement within `.text` (computed in pass 1; used
/// in pass 2 for both relocations and for the per-function code copy).
struct FnPlacement {
    /// Byte offset within `.text` where this function's first byte
    /// (the prologue's `push rbp`) lands.
    text_offset: u32,
}

/// Per-global placement within `.data`. mdbcc doesn't currently
/// separate `.bss` from `.data` (zero-initialised globals still carry
/// an explicit `bytes: vec![0; n]` from `global_image`); the converter
/// emits everything into `.data` to keep semantics identical to today's
/// pe.rs path. A future tick can introduce the split when codegen
/// preserves the `init.is_none()` flag.
struct DataPlacement {
    /// Byte offset within `.data` where this global's first byte lands.
    data_offset: u32,
    /// `Some(bytes)` when the global is a string-literal pointer
    /// (`T* g = "...";`): the linker fills the 8-byte slot with the
    /// string's address. We synthesise an extra `.Lstr.*` static for
    /// the string body and emit an Addr64 reloc here.
    ptr_str: Option<Vec<u8>>,
}

/// Per-vtable placement within `.rdata`.
struct VtablePlacement {
    /// Byte offset within `.rdata` where the first slot lands.
    rdata_offset: u32,
}

/// Per-typeinfo-entry placement within `.rdata`. Each entry is two
/// `u32`s (`class_rva`, `base_rva`); the personality function reads
/// them via the scope-table header.
struct TyinfoPlacement {
    /// Byte offset within `.rdata` where the entry's first byte lands.
    rdata_offset: u32,
}

/// Per-string placement within `.rdata`. Strings are deduped by content
/// across the entire module — multiple function-local `RipRef::Str`
/// references that name the same byte sequence resolve to the same
/// offset.
struct StringPlacement {
    /// Byte offset within `.rdata` where this string's first byte
    /// lands (the string is null-terminated).
    rdata_offset: u32,
    /// Unique string id == index into `string_order` (the nth unique
    /// string owns the nth `.Lstr.*` symbol). Stored so repeat lookups
    /// return it in O(1) instead of a linear `string_order` scan.
    id: usize,
}

// ---------------------------------------------------------------------------
// Converter
// ---------------------------------------------------------------------------

struct Converter<'a> {
    module: &'a Module,
    /// Per-function placement (parallel to `Module.funcs`).
    fn_placements: Vec<FnPlacement>,
    /// Per-function name → index into `Module.funcs`. Lets us decide
    /// whether a referenced function is defined in this TU (resolves
    /// to a `.text` static) or undefined (UNDEFINED EXTERNAL).
    fn_index: BTreeMap<String, usize>,
    /// Per-global placement (parallel to `Module.globals`).
    global_placements: Vec<DataPlacement>,
    /// Per-vtable placement (parallel to `Module.vtables`).
    vtable_placements: Vec<VtablePlacement>,
    /// Per-typeinfo-entry placement (parallel to `Module.typeinfo`).
    typeinfo_placements: Vec<TyinfoPlacement>,
    /// `string-content → .rdata offset` for module-wide dedup. The
    /// vector order is the canonical "first appearance" order; symbol
    /// names use this ordering (`.Lstr.<n>`).
    string_offsets: BTreeMap<Vec<u8>, StringPlacement>,
    /// Insertion-ordered string list (the symbol naming source — the
    /// nth `.Lstr.*` corresponds to the nth unique string).
    string_order: Vec<Vec<u8>>,
    /// Per (function_index, local_string_index) → unique string id in
    /// `string_order`. Lets us translate `RipRef::Str(idx)` to the
    /// shared `.Lstr.*` symbol that owns that content.
    str_id_for: Vec<Vec<usize>>,
    /// `.text` byte image (built during planning so we can copy it
    /// directly into the Section without re-iterating).
    text_image: Vec<u8>,
    /// `.data` byte image. Pointer-to-string globals carry their 8-byte
    /// slot as zero here; the encoder fills it via an Addr64 reloc.
    data_image: Vec<u8>,
    /// `.rdata` byte image. Strings, vtable slots, and typeinfo entries
    /// emit into this buffer in that order.
    rdata_image: Vec<u8>,
}

impl<'a> Converter<'a> {
    fn new(module: &'a Module) -> Self {
        let n_funcs = module.funcs.len();
        let mut fn_index = BTreeMap::new();
        for (i, f) in module.funcs.iter().enumerate() {
            fn_index.insert(f.name.clone(), i);
        }
        Self {
            module,
            fn_placements: Vec::with_capacity(n_funcs),
            fn_index,
            global_placements: Vec::with_capacity(module.globals.len()),
            vtable_placements: Vec::with_capacity(module.vtables.len()),
            typeinfo_placements: Vec::with_capacity(module.typeinfo.len()),
            string_offsets: BTreeMap::new(),
            string_order: Vec::new(),
            str_id_for: vec![Vec::new(); n_funcs],
            text_image: Vec::new(),
            data_image: Vec::new(),
            rdata_image: Vec::new(),
        }
    }

    /// Run the planning + emission passes. Pass 1 computes placements
    /// and builds the raw byte images; pass 2 (in `emit_object`) walks
    /// the placements to produce sections, symbols, and relocations.
    fn run(mut self) -> Object {
        self.plan_text();
        self.plan_rdata_strings();
        self.plan_data();
        self.plan_rdata_vtables();
        self.plan_rdata_typeinfo();
        self.emit_object()
    }

    // ---- planning -------------------------------------------------------

    /// Build the `.text` image and per-function placements. Functions
    /// are laid out in `Module.funcs` order; each function's offset is
    /// the running cursor padded up to `FN_ALIGN`. Padding bytes are
    /// `0xCC` (int3 — traps cleanly if accidentally executed by a
    /// mis-resolved jump).
    fn plan_text(&mut self) {
        for f in &self.module.funcs {
            // Align before laying out the function so the entry-point
            // offset is on a 16-byte boundary (helps the future COMDAT
            // story, costs at most 15 bytes per function).
            while !self.text_image.len().is_multiple_of(FN_ALIGN) {
                self.text_image.push(0xCC);
            }
            let offset = self.text_image.len() as u32;
            self.fn_placements.push(FnPlacement {
                text_offset: offset,
            });
            self.text_image.extend_from_slice(&f.code);
        }
    }

    /// Plan the `.rdata` strings. Two responsibilities:
    /// 1. Dedup strings module-wide (a literal that appears in two
    ///    functions becomes one entry in `.rdata`).
    /// 2. Build the per-function `str_id_for` map so the emit pass can
    ///    translate `RipRef::Str(local_idx)` to the shared `.Lstr.*`
    ///    symbol that owns its content.
    fn plan_rdata_strings(&mut self) {
        for (fi, f) in self.module.funcs.iter().enumerate() {
            for (local_idx, content) in f.strings.iter().enumerate() {
                let _ = local_idx;
                let id = if let Some(p) = self.string_offsets.get(content) {
                    // Already seen — the placement carries its string id.
                    p.id
                } else {
                    // First occurrence. Lay out at current rdata cursor,
                    // null-terminated.
                    let off = self.rdata_image.len() as u32;
                    self.rdata_image.extend_from_slice(content);
                    self.rdata_image.push(0);
                    let id = self.string_order.len();
                    self.string_offsets
                        .insert(content.clone(), StringPlacement { rdata_offset: off, id });
                    self.string_order.push(content.clone());
                    id
                };
                self.str_id_for[fi].push(id);
            }
        }
    }

    /// Plan the `.data` image. Mirrors `pe::build_data`:
    /// - Each global is 8-byte aligned (we round up the cursor).
    /// - A pointer-to-string global occupies 8 bytes; its string body
    ///   is appended to `.rdata` and the 8-byte slot is filled by an
    ///   `Addr64` reloc (emitted in the symbol pass).
    fn plan_data(&mut self) {
        for g in &self.module.globals {
            if g.is_extern {
                // S4.2#24: an extern declaration has no `.data` storage (it is an
                // UNDEFINED symbol). Push a placeholder placement so the index
                // stays parallel to `module.globals` (RipRef::Data(idx)).
                self.global_placements.push(DataPlacement {
                    data_offset: 0,
                    ptr_str: None,
                });
                continue;
            }
            while !self.data_image.len().is_multiple_of(8) {
                self.data_image.push(0);
            }
            let off = self.data_image.len() as u32;
            if let Some(s) = &g.ptr_str {
                // Append the string body to `.rdata` (deduped — same
                // semantics as pe::build_data, which appends without
                // dedup; we dedup here, which is strictly better).
                let mut content_with_nul = s.clone();
                // `ptr_str` already includes the trailing NUL (see
                // `compile_module`'s construction site). Trim a single
                // trailing NUL before checking dedup so the
                // string_offsets keying matches plan_rdata_strings.
                if content_with_nul.ends_with(&[0]) {
                    content_with_nul.pop();
                }
                let _ = self.intern_rdata_string(&content_with_nul);
                // 8 zero bytes occupied; Addr64 reloc fills it later.
                self.data_image.extend_from_slice(&[0u8; 8]);
                self.global_placements.push(DataPlacement {
                    data_offset: off,
                    ptr_str: Some(content_with_nul),
                });
            } else {
                self.data_image.extend_from_slice(&g.bytes);
                self.global_placements.push(DataPlacement {
                    data_offset: off,
                    ptr_str: None,
                });
            }
        }
    }

    /// Append a string to `.rdata` if not yet present, returning the
    /// shared string id. Called both by the function-string planning
    /// pass and by the global pointer-to-string planning pass.
    fn intern_rdata_string(&mut self, content: &[u8]) -> usize {
        if let Some(p) = self.string_offsets.get(content) {
            return p.id;
        }
        let off = self.rdata_image.len() as u32;
        self.rdata_image.extend_from_slice(content);
        self.rdata_image.push(0);
        let id = self.string_order.len();
        self.string_offsets
            .insert(content.to_vec(), StringPlacement { rdata_offset: off, id });
        self.string_order.push(content.to_vec());
        id
    }

    /// Pointer width in bytes for the module's target — a vtable slot (and a
    /// `ptr_str` global slot) holds one code/data pointer, which is 8 bytes on
    /// Win64 and 4 on Win32. Win64 keeps the historical `8` so the x64
    /// byte-identity baselines cannot move.
    fn ptr_bytes(&self) -> usize {
        match self.module.target {
            crate::codegen::target::TargetKind::Win64 => 8,
            crate::codegen::target::TargetKind::Win32 => 4,
        }
    }

    /// Plan the per-vtable layout. Each vtable contributes
    /// `slots.len() * ptr_bytes` bytes to `.rdata`; every slot byte is
    /// zero on the wire (the linker fills it via an `Addr64`/`Addr32` reloc
    /// against the target function symbol). An empty-named slot ("pure
    /// virtual") emits no reloc — the bytes stay zero.
    /// W6 (G55): the vtable RTTI/EH descriptor prefix is unconditional. The
    /// vtable symbol still points at the slot array, so virtual dispatch is
    /// unchanged, but every weak-folded vtable has the same bytes immediately
    /// before the symbol. G56: gating this on per-TU `dynamic_cast` use let a
    /// no-prefix weak vtable win the image-wide fold; dynamic_cast then read a
    /// neighboring slot as the complete-object adjustment and produced a bogus
    /// pointer. i386 EH also walks the base-chain word at `vtable - ptr_width`.
    fn vtable_rtti_prefix(&self) -> bool {
        true
    }

    fn plan_rdata_vtables(&mut self) {
        let pw = self.ptr_bytes();
        let rtti = self.vtable_rtti_prefix();
        for vt in &self.module.vtables {
            // Pointer-aligned so the slot pointers are naturally aligned
            // (8 on Win64, 4 on Win32).
            while !self.rdata_image.len().is_multiple_of(pw) {
                self.rdata_image.push(0);
            }
            // S4.5/B-09 RTTI: two `pw`-byte descriptor words immediately
            // BEFORE the vtable symbol. The first is a signed adjustment from
            // this subobject pointer to the complete object; the second is the
            // existing base/owner vtable link (filled by reloc or zero).
            // The vtable SYMBOL still points at the slots (after this prefix),
            // so ctor vptr-init and virtual dispatch keep pointing at the slot
            // array. The prefix itself is now unconditional so weak-folded
            // vtables have one ABI-compatible layout across all TUs.
            if rtti {
                match pw {
                    4 => self
                        .rdata_image
                        .extend_from_slice(&vt.this_adjust.to_le_bytes()),
                    8 => self
                        .rdata_image
                        .extend_from_slice(&(vt.this_adjust as i64).to_le_bytes()),
                    _ => unreachable!("unsupported pointer width"),
                }
                self.rdata_image.extend_from_slice(&vec![0u8; pw]);
            }
            let off = self.rdata_image.len() as u32;
            self.vtable_placements
                .push(VtablePlacement { rdata_offset: off });
            // `pw` zero bytes per slot; the encoder writes the address
            // via an Addr64/Addr32 reloc.
            for _ in &vt.slots {
                self.rdata_image.extend_from_slice(&vec![0u8; pw]);
            }
        }
    }

    /// Plan the per-typeinfo entry layout. Each entry is 8 bytes
    /// (`u32 class_rva`, `u32 base_rva`); the personality function
    /// walks them in declaration order. Both fields are 32-bit RVAs,
    /// filled via `Addr32nb` relocs against the corresponding vtable
    /// statics.
    fn plan_rdata_typeinfo(&mut self) {
        for _entry in &self.module.typeinfo {
            // 4-byte align — each entry is two u32s.
            while !self.rdata_image.len().is_multiple_of(4) {
                self.rdata_image.push(0);
            }
            let off = self.rdata_image.len() as u32;
            self.typeinfo_placements
                .push(TyinfoPlacement { rdata_offset: off });
            self.rdata_image.extend_from_slice(&[0u8; 8]);
        }
    }

    // ---- emission --------------------------------------------------------

    /// Pass 2: walk the planned placements + raw images and produce
    /// the final `Object`. Returns the populated Object directly.
    fn emit_object(mut self) -> Object {
        // S2b.2: tag the COFF machine word from the module's target. Win64
        // keeps the historical AMD64 default; Win32 emits i386. Relocation
        // kinds are translated per-machine in `RelocKind::to_wire` (S2c).
        let machine = match self.module.target {
            crate::codegen::target::TargetKind::Win64 => crate::coff::Machine::Amd64,
            crate::codegen::target::TargetKind::Win32 => crate::coff::Machine::I386,
        };
        let mut obj = Object {
            machine,
            ..Object::default()
        };

        // Plan which sections will be emitted (only non-empty ones).
        // Each section's 1-based index gets stored so symbols can
        // reference it later. The HLD requires section-definition
        // symbols immediately first in the symbol table — we collect
        // sections, then emit STATIC section symbols, then everything
        // else.
        let mut section_kinds: Vec<EmitSection> = Vec::new();
        if !self.text_image.is_empty() {
            section_kinds.push(EmitSection::Text);
        }
        if !self.data_image.is_empty() {
            section_kinds.push(EmitSection::Data);
        }
        if !self.rdata_image.is_empty() {
            section_kinds.push(EmitSection::Rdata);
        }
        // S2e: `.pdata`/`.xdata` are the **x64** SEH materialisation. x86
        // (Win32) uses a fs:[0] chain lowered inline into `.text` (the SEH
        // record is pushed in each try-bearing function's prologue), so a
        // PE32 image carries NO exception sections — gate on Win64. Win64 is
        // byte-for-byte unchanged.
        let needs_eh = matches!(
            self.module.target,
            crate::codegen::target::TargetKind::Win64
        ) && self.module.funcs.iter().any(|f| !f.try_scopes.is_empty());
        if needs_eh {
            section_kinds.push(EmitSection::Pdata);
            section_kinds.push(EmitSection::Xdata);
        }

        // Pre-compute each section's 1-based index in `Object.sections`.
        let mut section_ix: BTreeMap<EmitSection, u16> = BTreeMap::new();
        for (i, kind) in section_kinds.iter().enumerate() {
            section_ix.insert(*kind, (i + 1) as u16);
        }

        // Per-section relocation buffers. We collect relocations here,
        // then attach them to the Section at the very end (we need to
        // know symbol indices first, which requires symbol-table
        // construction).
        let mut text_relocs: Vec<PendingReloc> = Vec::new();
        let mut data_relocs: Vec<PendingReloc> = Vec::new();
        let mut rdata_relocs: Vec<PendingReloc> = Vec::new();
        let mut pdata_relocs: Vec<PendingReloc> = Vec::new();
        let mut xdata_relocs: Vec<PendingReloc> = Vec::new();

        // -------- Section symbols (the first STATIC entries) ---------
        //
        // One STATIC section-def symbol per emitted section (in section
        // header order). Each carries a single Aux Format 5 record.
        // Symbols are added to `obj.symbols`; we record their index so
        // the symbol-table population below can reuse them. The aux's
        // `length`/`num_relocs` are populated AFTER we know the relocs
        // (deferred patch below).
        let mut section_symbol_ix: BTreeMap<EmitSection, usize> = BTreeMap::new();
        for kind in &section_kinds {
            let name = kind.canonical_section_name();
            let sym_ix = obj.symbols.len();
            section_symbol_ix.insert(*kind, sym_ix);
            obj.symbols.push(Symbol {
                name: SymName::from_str(name, &mut obj.strtab),
                value: 0,
                section: SectionRef::Section(section_ix[kind]),
                kind: SymKind::Notype,
                storage: StorageClass::Static,
                aux: vec![AuxRecord::SectionDef {
                    length: 0,
                    num_relocs: 0,
                    checksum: 0,
                    number: 0,
                    selection: None,
                }],
            });
        }

        // -------- Defined-function EXTERNAL symbols ------------------
        //
        // One EXTERNAL symbol per defined function. Symbol indices land
        // in `fn_sym_ix` (parallel to Module.funcs) so reloc emission
        // can look them up.
        let mut fn_sym_ix: Vec<usize> = Vec::with_capacity(self.module.funcs.len());
        let text_section_ix = section_ix.get(&EmitSection::Text).copied();
        for (i, f) in self.module.funcs.iter().enumerate() {
            let sym_ix = obj.symbols.len();
            fn_sym_ix.push(sym_ix);
            obj.symbols.push(Symbol {
                name: SymName::from_str(&f.name, &mut obj.strtab),
                value: self.fn_placements[i].text_offset,
                section: text_section_ix
                    .map(SectionRef::Section)
                    .unwrap_or(SectionRef::Undefined),
                kind: SymKind::Function,
                // S4.2af/S4.2ah: an inline-emitted function (header member /
                // operator / template body) is identical in every TU that uses
                // it, so it is WeakExternal — the linker folds cross-object
                // duplicates. A free function is emitted once and stays a
                // strong External.
                //
                // S4.2ah: ALSO fold any SOURCE-FORM member function — a name
                // that is qualified (`Tag::member`) but NOT Borland-mangled
                // (mangled symbols begin with `@`). mdbcc emits compiler-
                // SYNTHESISED members (e.g. a memberwise `TRegexp::operator=`
                // pulled in by OPRASGN2/OPRASGN3) under their source name, and
                // every using TU emits an identical copy — so they fold like
                // any other implicit special member. (A single-TU image still
                // resolves a lone weak def identically ⇒ 88 baselines
                // byte-identical.)
                // W6 (G50c): the reserved `.mdbcc_ctor.` thunks are EXEMPT
                // from the S4.2ah source-form-member fold — a ctor thunk for
                // a QUALIFIED static member (`.mdbcc_ctor.TApplication::
                // InitCmdLine`, OWL APPLICAT.CPP) contains `::` but is a
                // unique strong definition, and `collect_ctor_thunks` only
                // collects External symbols: the WeakExternal mis-class left
                // the thunk OUT of the entry stub's call list (InitCmdLine
                // never constructed — railc startup crash, take 7).
                storage: if !f.name.starts_with(".mdbcc_ctor.")
                    && (f.inline || (!f.name.starts_with('@') && f.name.contains("::")))
                {
                    StorageClass::WeakExternal
                } else {
                    StorageClass::External
                },
                aux: Vec::new(),
            });
        }

        // -------- STATIC globals in .data ----------------------------
        //
        // One STATIC data symbol per global, named with the global's
        // own name (Borland mangling already applied where applicable —
        // `module.globals` carries plain names plus the synthesised
        // `.flit.<fn>.<i>` / `.mdbcc_eh_buffer` / `.mdbcc_eh_save`
        // forms). STATIC keeps the symbol TU-local (the typical case
        // for file-scope globals); promotion to External is a S1c
        // concern when cross-TU references happen.
        let mut global_sym_ix: Vec<usize> = Vec::with_capacity(self.module.globals.len());
        let data_section_ix = section_ix.get(&EmitSection::Data).copied();
        for (i, g) in self.module.globals.iter().enumerate() {
            let sym_ix = obj.symbols.len();
            global_sym_ix.push(sym_ix);
            // S4.2#24: an `extern T g;` declaration emits an UNDEFINED EXTERNAL
            // symbol (no section, no .data) that the linker resolves against the
            // defining TU; a real definition stays a defined .data symbol.
            let (value, section, storage) = if g.is_extern {
                (0, SectionRef::Undefined, StorageClass::External)
            } else {
                // S4.2#24: a USER file-scope global has EXTERNAL linkage (visible
                // cross-TU — the defining side of an `extern` reference, and the
                // C linkage model). mdbcc-internal globals (`.flit`, `.slocal`,
                // `.mdbcc_ctor`, `.mdbcc_eh_*`) are per-TU implementation detail
                // and stay Static/local so they never collide across objects.
                // S4 (#48): a namespace-scope `const` (unqualified) has INTERNAL
                // linkage in C++, so it is TU-local (Static) — multiple TUs that
                // include the same `const T X = v;` header (`const size_t NPOS =
                // size_t(-1);` in cstring.h) then do not collide at link. A
                // QUALIFIED `Tag::member` const is a static DATA MEMBER
                // definition (external, one per program), so it stays External.
                let storage = if g.name.starts_with('.') || (g.is_const && !g.name.contains("::")) {
                    StorageClass::Static
                } else {
                    StorageClass::External
                };
                (
                    self.global_placements[i].data_offset,
                    data_section_ix
                        .map(SectionRef::Section)
                        .unwrap_or(SectionRef::Undefined),
                    storage,
                )
            };
            obj.symbols.push(Symbol {
                name: SymName::from_str(&g.name, &mut obj.strtab),
                value,
                section,
                kind: SymKind::Notype,
                storage,
                aux: Vec::new(),
            });
        }

        // -------- STATIC string-literal symbols in .rdata ------------
        //
        // One per unique string. Named `.Lstr.<n>` where `n` is the
        // insertion order in `string_order`.
        let mut str_sym_ix: Vec<usize> = Vec::with_capacity(self.string_order.len());
        let rdata_section_ix = section_ix.get(&EmitSection::Rdata).copied();
        for (i, content) in self.string_order.iter().enumerate() {
            let sym_ix = obj.symbols.len();
            str_sym_ix.push(sym_ix);
            let name = format!("{STR_PREFIX}.{i}");
            let placement = &self.string_offsets[content];
            obj.symbols.push(Symbol {
                name: SymName::from_str(&name, &mut obj.strtab),
                value: placement.rdata_offset,
                section: rdata_section_ix
                    .map(SectionRef::Section)
                    .unwrap_or(SectionRef::Undefined),
                kind: SymKind::Notype,
                storage: StorageClass::Static,
                aux: Vec::new(),
            });
        }

        // -------- STATIC vtable symbols in .rdata --------------------
        //
        // One STATIC `.Lvtbl.<rec_id>` per vtable. Also emit a more
        // descriptive `borland_vtable_symbol(tag)` alias when the
        // record has a tag — this is the symbol bcc32 emits (`@Bar@3`),
        // useful for O13 differential comparisons. The two share the
        // same offset so a reloc against either resolves identically.
        // W6 (G54): a TAGGED class's vtable is emitted under its LINK-
        // CANONICAL bcc32 name (`@Tag@3`) as WeakExternal, so mdlink FOLDS
        // the per-TU copies and every `RipRef::Vtable` reloc — including the
        // EH type tags the personality compares by RVA — resolves to ONE
        // address image-wide (a class thrown in TU A now matches a `catch`
        // in TU B). Tag-less / synthetic vtables keep the historical
        // TU-local `.Lvtbl.<id>` static.
        let mut vtable_sym_ix: Vec<usize> = Vec::with_capacity(self.module.vtables.len());
        for (i, vt) in self.module.vtables.iter().enumerate() {
            let sym_ix = obj.symbols.len();
            vtable_sym_ix.push(sym_ix);
            let placement = &self.vtable_placements[i];
            let (name, storage) = match &vt.weak_sym {
                Some(canon) => (canon.clone(), StorageClass::WeakExternal),
                None => (format!("{VTABLE_PREFIX}.{}", vt.id), StorageClass::Static),
            };
            obj.symbols.push(Symbol {
                name: SymName::from_str(&name, &mut obj.strtab),
                value: placement.rdata_offset,
                section: rdata_section_ix
                    .map(SectionRef::Section)
                    .unwrap_or(SectionRef::Undefined),
                kind: SymKind::Notype,
                storage,
                aux: Vec::new(),
            });
        }

        // -------- STATIC typeinfo entry symbols in .rdata ------------
        //
        // One STATIC `.Lxt.<rec_id>` per typeinfo entry. The `.xdata`
        // scope-table header references the FIRST entry as the table
        // base (matching the personality function's read pattern).
        // W6 (G54): same canonical-fold treatment for typeinfo entries —
        // bcc32's `@$xt$<encoding>` WeakExternal. A NON-polymorphic class's
        // EH identity is its typeinfo-entry RVA, so cross-TU folding is what
        // lets `catch (xmsg&)` match an `xmsg` thrown in another TU.
        let mut typeinfo_sym_ix: Vec<usize> = Vec::with_capacity(self.module.typeinfo.len());
        for (i, entry) in self.module.typeinfo.iter().enumerate() {
            let sym_ix = obj.symbols.len();
            typeinfo_sym_ix.push(sym_ix);
            let placement = &self.typeinfo_placements[i];
            let (name, storage) = match &entry.weak_sym {
                Some(canon) => (canon.clone(), StorageClass::WeakExternal),
                None => (
                    format!("{TYPEINFO_PREFIX}.{}", entry.class_record_id),
                    StorageClass::Static,
                ),
            };
            obj.symbols.push(Symbol {
                name: SymName::from_str(&name, &mut obj.strtab),
                value: placement.rdata_offset,
                section: rdata_section_ix
                    .map(SectionRef::Section)
                    .unwrap_or(SectionRef::Undefined),
                kind: SymKind::Notype,
                storage,
                aux: Vec::new(),
            });
        }

        // -------- Pending UNDEFINED EXTERNAL symbols -----------------
        //
        // We collect undefined externals (imported function names, RTL
        // helpers, function-pointer targets to functions defined in
        // another TU) by walking every CallSite + RipRef. Two key
        // determinism properties:
        // 1. We DON'T iterate a HashMap to populate emitted bytes — the
        //    walk is over Vec-ordered Module.funcs.
        // 2. We dedup by name into a Vec, preserving first-appearance
        //    order, then SORT lexicographically so the final symbol
        //    order is a pure function of the name set.
        let mut undef_names: Vec<String> = Vec::new();
        let mut undef_seen: BTreeMap<String, ()> = BTreeMap::new();
        // J-8b (tick 74): track the first CallSite loc per undefined-extern
        // name so the linker can render `"line:col: unresolved external
        // function 'X'"` when a reloc has no resolved target. Only call
        // sites (not RipRef::Import or extern_refs) carry meaningful Locs.
        let mut undef_first_loc: BTreeMap<String, (u32, u32)> = BTreeMap::new();
        let add_undef = |name: String, seen: &mut BTreeMap<String, ()>, out: &mut Vec<String>| {
            if !seen.contains_key(&name) {
                seen.insert(name.clone(), ());
                out.push(name);
            }
        };
        for f in &self.module.funcs {
            for cs in &f.calls {
                if !self.fn_index.contains_key(&cs.callee) {
                    add_undef(cs.callee.clone(), &mut undef_seen, &mut undef_names);
                    if !cs.loc.is_synthetic() {
                        undef_first_loc
                            .entry(cs.callee.clone())
                            .or_insert((cs.loc.line, cs.loc.col));
                    }
                }
            }
            for r in &f.riprefs {
                match &r.target {
                    RipRef::Import(name) => {
                        let imp = format!("__imp_{name}");
                        add_undef(imp, &mut undef_seen, &mut undef_names);
                    }
                    RipRef::Func(name) => {
                        if !self.fn_index.contains_key(name) {
                            add_undef(name.clone(), &mut undef_seen, &mut undef_names);
                        }
                    }
                    RipRef::Str(_) | RipRef::Data(_) | RipRef::Vtable(_) => {}
                }
            }
            // S1b.7 (RED 1): shadow extern refs the inlined libc paths
            // produced (e.g. `_puts` from `gen_io_builtin`). These name
            // UNDEFINED EXTERNAL symbols that no reloc references — they
            // exist purely to keep the COFF symbol set aligned with
            // bcc32's OMF EXTDEFs (O13 parity contract). If a symbol
            // here happens to be defined in this TU, skip it (the
            // definition wins).
            for name in &f.extern_refs {
                if !self.fn_index.contains_key(name) {
                    add_undef(name.clone(), &mut undef_seen, &mut undef_names);
                }
            }
        }
        // S4.2d: a vtable slot may reference a virtual that is DECLARED in this
        // TU but DEFINED in another (the RTL — e.g. `typeinfo::~typeinfo`, or any
        // OWL class whose virtuals live in `owl.lib`). Register such a slot's
        // symbol as an undefined external so its `.rdata` reloc resolves at link
        // time (S5), instead of panicking in the reloc loop below. Byte-identical
        // for every existing program (all of whose slots are defined in-TU).
        for vt in &self.module.vtables {
            for sym in &vt.slots {
                if !sym.is_empty() && !self.fn_index.contains_key(sym) {
                    add_undef(sym.clone(), &mut undef_seen, &mut undef_names);
                }
            }
        }
        undef_names.sort();
        let mut undef_sym_ix: BTreeMap<String, usize> = BTreeMap::new();
        let mut undef_loc_slots: Vec<(usize, (u32, u32))> = Vec::new();
        for name in &undef_names {
            let sym_ix = obj.symbols.len();
            undef_sym_ix.insert(name.clone(), sym_ix);
            if let Some(loc) = undef_first_loc.get(name) {
                undef_loc_slots.push((sym_ix, *loc));
            }
            // Externals via the import convention are functions per
            // COFF (`SymKind::Function`); plain externs are notype.
            // We don't know which way it is for a generic name, so use
            // Function as the default — it's the safe choice for the
            // linker (lld-link doesn't care about Type for UNDEFINED).
            obj.symbols.push(Symbol {
                name: SymName::from_str(name, &mut obj.strtab),
                value: 0,
                section: SectionRef::Undefined,
                kind: SymKind::Function,
                storage: StorageClass::External,
                aux: Vec::new(),
            });
        }

        // -------- .text relocations ----------------------------------
        //
        // For each function we walk its CallSite + RipRef lists. Each
        // patch site becomes one COFF Reloc against the appropriate
        // symbol. The patch-site offset is function-local (`cs.at`,
        // `r.at`) — we add the function's `.text` offset to get the
        // section-relative offset.
        for (fi, f) in self.module.funcs.iter().enumerate() {
            let base = self.fn_placements[fi].text_offset;
            for cs in &f.calls {
                let sym_ix = if let Some(target_ix) = self.fn_index.get(&cs.callee) {
                    fn_sym_ix[*target_ix]
                } else {
                    undef_sym_ix[&cs.callee]
                };
                text_relocs.push(PendingReloc {
                    offset: base + cs.at as u32,
                    symbol: sym_ix as u32,
                    kind: RelocKind::Rel32,
                });
            }
            for r in &f.riprefs {
                let sym_ix = match &r.target {
                    RipRef::Import(name) => {
                        let imp = format!("__imp_{name}");
                        undef_sym_ix[&imp]
                    }
                    RipRef::Str(idx) => {
                        let id = self.str_id_for[fi][*idx];
                        str_sym_ix[id]
                    }
                    RipRef::Data(idx) => global_sym_ix[*idx],
                    RipRef::Func(name) => {
                        if let Some(target_ix) = self.fn_index.get(name) {
                            fn_sym_ix[*target_ix]
                        } else {
                            undef_sym_ix[name]
                        }
                    }
                    RipRef::Vtable(rec_id) => {
                        // S4.2ae: a polymorphic class's EH type tag is its
                        // vtable symbol; a NON-polymorphic one's is its OWN
                        // typeinfo-entry symbol (`.Lxt.<id>`) — the entry
                        // doubles as the type descriptor (its address is the
                        // identity, and its `class_rva` self-references, so a
                        // thrown non-poly tag matches its own entry).
                        if let Some(vt_ix) =
                            self.module.vtables.iter().position(|vt| vt.id == *rec_id)
                        {
                            vtable_sym_ix[vt_ix]
                        } else if let Some(ti_ix) = self
                            .module
                            .typeinfo
                            .iter()
                            .position(|e| e.class_record_id == *rec_id)
                        {
                            typeinfo_sym_ix[ti_ix]
                        } else {
                            panic!(
                                "S4.2ae: RipRef::Vtable({rec_id}) has neither \
                                 a vtable nor a typeinfo entry (codegen \
                                 invariant violation)"
                            )
                        }
                    }
                };
                // S2b.2d: on x86 a data/import reference is an absolute
                // `[disp32]` (DIR32/Addr32), not RIP-relative — the linker
                // fills it with `image_base + target_rva`. On x64 every
                // RipRef-derived `.text` reloc stays REL32 (RIP-relative),
                // byte-for-byte as before. Direct `call rel32` sites (the
                // `f.calls` loop above) stay REL32 on both targets — relative
                // calls work on x86 too.
                let kind = match self.module.target {
                    crate::codegen::target::TargetKind::Win32 => RelocKind::Addr32,
                    crate::codegen::target::TargetKind::Win64 => RelocKind::Rel32,
                };
                text_relocs.push(PendingReloc {
                    offset: base + r.at as u32,
                    symbol: sym_ix as u32,
                    kind,
                });
            }
        }

        // Absolute-pointer reloc kind for the active target: `Addr64` (8-byte
        // slot) on Win64, `Addr32` (4-byte slot) on Win32. S5: the ptr_str /
        // ptr_global loops below previously hardcoded `Addr64`, which PANICKED
        // at COFF write time on i386 (`RelocKindUnsupported(Addr64, I386)`) —
        // hit by any i386 TU with a `T *g = &other;` global (RTL FMODEPTR.C
        // `int *_fmodeptr = &_fmode;`, OWL CLIPBOAR.CPP). The slot bytes were
        // already pointer-width-correct (`global_image` sizes by target); only
        // the reloc kind was Win64-fixed.
        let abs_reloc_kind = match self.module.target {
            crate::codegen::target::TargetKind::Win64 => RelocKind::Addr64,
            crate::codegen::target::TargetKind::Win32 => RelocKind::Addr32,
        };

        // -------- .data relocations (ptr_str globals) ----------------
        //
        // Every pointer-to-string global needs its pointer-width slot filled
        // with the string's absolute address (reloc against the shared
        // `.Lstr.*` static).
        for (i, g) in self.module.globals.iter().enumerate() {
            if let Some(content) = &self.global_placements[i].ptr_str {
                let _ = g;
                let str_id = self
                    .string_offsets
                    .get(content)
                    .expect(
                        "ptr_str global was interned during plan_data but is \
                         missing from string_order — converter invariant \
                         violation",
                    )
                    .id;
                data_relocs.push(PendingReloc {
                    offset: self.global_placements[i].data_offset,
                    symbol: str_sym_ix[str_id] as u32,
                    kind: abs_reloc_kind,
                });
            }
        }

        // -------- .data relocations (ptr_global globals) -------------
        //
        // S5 #45: `T *g = &other;` — the pointer-width slot is filled with the
        // TARGET global's absolute address (reloc against the target's `.data`
        // symbol). The target was validated as a real data global at codegen
        // time (`sigs.globals.contains_key`), so the index lookup always hits;
        // `global_sym_ix` is parallel to `module.globals`. The zero bytes were
        // already laid into `.data` by `plan_data`'s ordinary `g.bytes` path.
        for (i, g) in self.module.globals.iter().enumerate() {
            if let Some(target) = &g.ptr_global {
                let tgt_idx = self
                    .module
                    .globals
                    .iter()
                    .position(|x| &x.name == target)
                    .expect("ptr_global target missing from module.globals");
                data_relocs.push(PendingReloc {
                    offset: self.global_placements[i].data_offset,
                    symbol: global_sym_ix[tgt_idx] as u32,
                    kind: abs_reloc_kind,
                });
            }
        }

        // -------- .data relocations (G52 aggregate-element relocs) ----
        //
        // W6 (G52): the GENERAL form — one absolute reloc per ADDRESS-
        // CONSTANT element inside an aggregate image (`char * const
        // _tzname[2] = {&_DfltZone[0], …}`, TZSET.C). The addend was
        // written into the slot bytes by `global_image_reloc`; Addr32/
        // Addr64 add-in-place semantics complete the address. Targets were
        // validated against `sigs.globals` at codegen time.
        for (i, g) in self.module.globals.iter().enumerate() {
            for (off, target, _addend) in &g.data_relocs {
                let tgt_idx = self
                    .module
                    .globals
                    .iter()
                    .position(|x| &x.name == target)
                    .expect("data_relocs target missing from module.globals");
                data_relocs.push(PendingReloc {
                    offset: self.global_placements[i].data_offset + *off as u32,
                    symbol: global_sym_ix[tgt_idx] as u32,
                    kind: abs_reloc_kind,
                });
            }
        }

        // -------- .rdata relocations (vtable slots, typeinfo) --------
        //
        // Each vtable slot's pointer bytes are filled by an absolute reloc
        // against the target function symbol — `Addr64` (8 bytes) on Win64,
        // `Addr32` (4 bytes) on Win32. Empty-named slots are pure virtual —
        // no reloc, the bytes stay zero.
        let pw = self.ptr_bytes();
        let slot_reloc_kind = abs_reloc_kind;
        for (i, vt) in self.module.vtables.iter().enumerate() {
            let base = self.vtable_placements[i].rdata_offset;
            for (slot_ix, sym) in vt.slots.iter().enumerate() {
                if sym.is_empty() {
                    continue;
                }
                let target_sym_ix = if let Some(target_ix) = self.fn_index.get(sym) {
                    fn_sym_ix[*target_ix]
                } else {
                    // Vtable slots referring to functions not defined in
                    // this TU is theoretically possible for COMDAT
                    // virtual functions; today's mdbcc never produces
                    // one, but the spec accommodates it via UNDEFINED.
                    *undef_sym_ix.get(sym).unwrap_or_else(|| {
                        panic!(
                            "S1b.4: vtable slot '{sym}' refers to an \
                             unknown function (not in this TU and not \
                             registered as an undefined external)"
                        )
                    })
                };
                rdata_relocs.push(PendingReloc {
                    offset: base + (slot_ix * pw) as u32,
                    symbol: target_sym_ix as u32,
                    kind: slot_reloc_kind,
                });
            }
            // S4.5 RTTI: fill the descriptor word at `base - pw` with the BASE
            // class's vtable address (the dynamic_cast base-chain link). A root
            // (base_id None) or an out-of-TU base leaves it zero (chain end).
            if self.vtable_rtti_prefix()
                && let Some(base_vt_ix) = vt
                    .base_id
                    .and_then(|bid| self.module.vtables.iter().position(|v| v.id == bid))
            {
                rdata_relocs.push(PendingReloc {
                    offset: base - pw as u32,
                    symbol: vtable_sym_ix[base_vt_ix] as u32,
                    kind: slot_reloc_kind,
                });
            }
        }
        // Typeinfo entries: each is `class_rva` (Addr32nb against the
        // class vtable static) + `base_rva` (Addr32nb against the base
        // vtable static, or zero if no base).
        for (i, entry) in self.module.typeinfo.iter().enumerate() {
            let base = self.typeinfo_placements[i].rdata_offset;
            // S4.2ae: class_rva points at the class's EH type tag — its vtable
            // (polymorphic) or its OWN typeinfo entry (non-polymorphic: the
            // entry-as-descriptor, so class_rva self-references and a thrown
            // non-poly tag — which IS this entry's address — matches here).
            let class_sym = if let Some(vt_ix) = self
                .module
                .vtables
                .iter()
                .position(|vt| vt.id == entry.class_record_id)
            {
                vtable_sym_ix[vt_ix]
            } else {
                typeinfo_sym_ix[i]
            };
            rdata_relocs.push(PendingReloc {
                offset: base,
                symbol: class_sym as u32,
                kind: RelocKind::Addr32nb,
            });
            if let Some(base_rec_id) = entry.base_record_id {
                // S4.2ae: base_rva → the base's type tag (its vtable, or its
                // typeinfo entry when the base is non-polymorphic). A base not
                // in typeinfo (not EH-live) leaves the 4 bytes zero ("root"),
                // matching the prior unresolved-base behaviour.
                let base_sym = if let Some(base_vt_ix) = self
                    .module
                    .vtables
                    .iter()
                    .position(|vt| vt.id == base_rec_id)
                {
                    Some(vtable_sym_ix[base_vt_ix])
                } else {
                    self.module
                        .typeinfo
                        .iter()
                        .position(|e| e.class_record_id == base_rec_id)
                        .map(|ti| typeinfo_sym_ix[ti])
                };
                if let Some(bs) = base_sym {
                    rdata_relocs.push(PendingReloc {
                        offset: base + 4,
                        symbol: bs as u32,
                        kind: RelocKind::Addr32nb,
                    });
                }
            }
        }

        // -------- .pdata / .xdata for SEH ----------------------------
        //
        // One RUNTIME_FUNCTION (12 bytes) per function — BeginAddress,
        // EndAddress, UnwindInfoAddress. All three are Addr32nb relocs.
        let (pdata_image, xdata_image) = if needs_eh {
            self.build_eh_sections(
                &fn_sym_ix,
                &vtable_sym_ix,
                &typeinfo_sym_ix,
                &mut pdata_relocs,
                &mut xdata_relocs,
            )
        } else {
            (Vec::new(), Vec::new())
        };

        // -------- Build & push sections ------------------------------
        //
        // We add sections in the order they were planned. Per-section
        // relocations are attached now that we know the symbol indices.
        for kind in &section_kinds {
            let mut sec = match kind {
                EmitSection::Text => {
                    let mut s = Section::text();
                    s.data = std::mem::take(&mut self.text_image);
                    s.relocs = text_relocs
                        .iter()
                        .copied()
                        .map(PendingReloc::to_coff)
                        .collect();
                    s
                }
                EmitSection::Data => {
                    let mut s = Section::data();
                    s.data = std::mem::take(&mut self.data_image);
                    s.relocs = data_relocs
                        .iter()
                        .copied()
                        .map(PendingReloc::to_coff)
                        .collect();
                    s
                }
                EmitSection::Rdata => {
                    let mut s = Section::rdata();
                    s.data = std::mem::take(&mut self.rdata_image);
                    s.relocs = rdata_relocs
                        .iter()
                        .copied()
                        .map(PendingReloc::to_coff)
                        .collect();
                    s
                }
                EmitSection::Pdata => {
                    let mut s = Section::pdata();
                    s.data = pdata_image.clone();
                    s.relocs = pdata_relocs
                        .iter()
                        .copied()
                        .map(PendingReloc::to_coff)
                        .collect();
                    s
                }
                EmitSection::Xdata => {
                    let mut s = Section::xdata();
                    s.data = xdata_image.clone();
                    s.relocs = xdata_relocs
                        .iter()
                        .copied()
                        .map(PendingReloc::to_coff)
                        .collect();
                    s
                }
            };
            // Patch the SectionDef aux record for this section symbol
            // with the final length + reloc count.
            let sym_ix = section_symbol_ix[kind];
            if let Some(AuxRecord::SectionDef {
                length, num_relocs, ..
            }) = obj.symbols[sym_ix].aux.first_mut()
            {
                *length = sec.data.len() as u32;
                *num_relocs = sec.relocs.len() as u16;
            }
            // The section data has been moved out via std::mem::take
            // for the .text/.data/.rdata paths above; the assignment
            // into `sec.data` happened before we got here. No further
            // action needed.
            // (Future enhancement: the `.bss` path will set
            // `sec.bss_size` and leave `sec.data` empty. The current
            // converter never produces a .bss section.)
            let _ = &mut sec;
            obj.sections.push(sec);
        }

        // J-8b: thread per-symbol source locs through Object so the linker
        // can render line/col diagnostics for unresolved externals. Most
        // entries are None (defined symbols, statics, section symbols);
        // undefined externals introduced by a CallSite get the first such
        // site's loc.
        obj.symbol_source_locs = vec![None; obj.symbols.len()];
        for (sym_ix, (line, col)) in undef_loc_slots {
            obj.symbol_source_locs[sym_ix] = Some((line, col));
        }

        obj
    }

    /// Build the `.pdata` + `.xdata` images plus the relocations that
    /// patch their address fields. Mirrors `pe::build_pdata` and
    /// `pe::build_xdata` minus the RVA arithmetic — every absolute /
    /// relative address becomes a COFF reloc against the appropriate
    /// symbol.
    fn build_eh_sections(
        &self,
        fn_sym_ix: &[usize],
        vtable_sym_ix: &[usize],
        typeinfo_sym_ix: &[usize],
        pdata_relocs: &mut Vec<PendingReloc>,
        xdata_relocs: &mut Vec<PendingReloc>,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut pdata = Vec::new();
        let mut xdata = Vec::new();
        // Per-function `.xdata` offset so the `.pdata` UnwindInfoAddress
        // reloc lands on the right symbol+addend. Leaf tail-jump thunks do not
        // need unwind metadata, so their slot stays None and the `.pdata` pass
        // skips them.
        let mut fn_xdata_off: Vec<Option<u32>> = vec![None; self.module.funcs.len()];

        // We need a STATIC symbol for the .xdata section itself; that's
        // already the section-def symbol, which lives at a known index.
        // We don't have it threaded through here; instead we manufacture
        // a synthesised reloc target via the section symbol — the caller
        // populated section symbols at the START of obj.symbols, so we
        // can pre-compute them. To stay self-contained we pass the
        // current section symbol index via a small helper.
        //
        // The caller has already populated section symbols; their indices
        // map to EmitSection in the order they were added. We re-derive
        // here.
        let xdata_section_sym = self.section_symbol_index_for(EmitSection::Xdata);

        // First pass: build the .xdata image so we know each function's
        // offset within it (the value the `.pdata` UnwindInfoAddress
        // field needs).
        for (fi, f) in self.module.funcs.iter().enumerate() {
            if is_unwindless_thunk(f) {
                assert!(
                    f.try_scopes.is_empty(),
                    "internal: thunk '{}' unexpectedly carries try scopes",
                    f.name
                );
                continue;
            }
            while !xdata.len().is_multiple_of(4) {
                xdata.push(0);
            }
            fn_xdata_off[fi] = Some(xdata.len() as u32);

            let has_try = !f.try_scopes.is_empty();
            let alloc = read_prolog_alloc(&f.code).unwrap_or_else(|e| {
                panic!(
                    "S1b.4: function '{}' prologue does not match the \
                     mdbcc-expected shape ({e}); pe.rs would have rejected \
                     this with the same diagnostic",
                    f.name
                )
            });
            if alloc == 0 || !alloc.is_multiple_of(8) {
                panic!(
                    "S1b.4: function '{}' prologue allocates {alloc} bytes \
                     — must be a non-zero multiple of 8 for UNWIND_INFO",
                    f.name
                );
            }

            // Build UNWIND_INFO bytes per the same algorithm pe::build_xdata
            // uses (alloc-small / alloc-large / alloc-large-large
            // discriminator).
            let (alloc_codes, alloc_extra) = if alloc <= 128 {
                let opinfo = ((alloc / 8) - 1) as u8;
                let code = [
                    MDBCC_PROLOG_SUB_RSP_OFFSET,
                    (opinfo << 4) | UWOP_ALLOC_SMALL,
                ];
                (1u8, code.to_vec())
            } else if alloc < 512 * 1024 {
                let scaled = (alloc / 8) as u16;
                let header = [MDBCC_PROLOG_SUB_RSP_OFFSET, UWOP_ALLOC_LARGE];
                let mut buf = header.to_vec();
                buf.extend_from_slice(&scaled.to_le_bytes());
                (2u8, buf)
            } else {
                let header = [MDBCC_PROLOG_SUB_RSP_OFFSET, (1 << 4) | UWOP_ALLOC_LARGE];
                let mut buf = header.to_vec();
                buf.extend_from_slice(&alloc.to_le_bytes());
                (3u8, buf)
            };
            let push_rbp = [
                MDBCC_PROLOG_PUSH_RBP_OFFSET,
                (UWOP_OPINFO_RBP << 4) | UWOP_PUSH_NONVOL,
            ];
            let count = alloc_codes + 1;
            let flags = if has_try { UNW_FLAG_EHANDLER } else { 0 };

            xdata.push(1 | (flags << 3));
            xdata.push(MDBCC_PROLOG_SIZE);
            xdata.push(count);
            xdata.push(0);
            xdata.extend_from_slice(&alloc_extra);
            xdata.extend_from_slice(&push_rbp);
            if count % 2 != 0 {
                xdata.push(0);
                xdata.push(0);
            }

            if has_try {
                // ExceptionHandler RVA — Addr32nb against the
                // personality function. We resolve PERSONALITY_FN_NAME
                // through fn_index since pe.rs always emits the
                // personality function as the last module func.
                let personality_offset = xdata.len() as u32;
                xdata.extend_from_slice(&[0u8; 4]); // patched by reloc
                let personality_ix = *self.fn_index.get(PERSONALITY_FN_NAME).unwrap_or_else(|| {
                    panic!(
                        "S1b.4: TU has try-bearing functions but no \
                             personality function defined (compile_module \
                             should have synthesised one)"
                    )
                });
                xdata_relocs.push(PendingReloc {
                    offset: personality_offset,
                    symbol: fn_sym_ix[personality_ix] as u32,
                    kind: RelocKind::Addr32nb,
                });

                // Scope table header: scope_count (u32), tyinf_rva
                // (Addr32nb against the first typeinfo entry, or 0
                // when no typeinfo exists), tyinf_count (u32).
                let scope_count = f.try_scopes.len() as u32;
                xdata.extend_from_slice(&scope_count.to_le_bytes());

                let tyinf_rva_offset = xdata.len() as u32;
                xdata.extend_from_slice(&[0u8; 4]);
                if !self.module.typeinfo.is_empty() {
                    xdata_relocs.push(PendingReloc {
                        offset: tyinf_rva_offset,
                        symbol: typeinfo_sym_ix[0] as u32,
                        kind: RelocKind::Addr32nb,
                    });
                }

                let tyinf_count = self.module.typeinfo.len() as u32;
                xdata.extend_from_slice(&tyinf_count.to_le_bytes());

                // Per-scope entries (20 bytes each).
                for s in &f.try_scopes {
                    let try_begin_offset = xdata.len() as u32;
                    xdata.extend_from_slice(&[0u8; 4]);
                    xdata_relocs.push(PendingReloc {
                        offset: try_begin_offset,
                        symbol: fn_sym_ix[fi] as u32,
                        kind: RelocKind::Addr32nb,
                    });
                    // The "addend" for an Addr32nb is encoded in the
                    // section bytes (the 4 bytes at `offset`). We write
                    // it now so the linker resolves to func_rva + addend.
                    let last = xdata.len();
                    let try_begin_disp = s.try_begin;
                    xdata[last - 4..last].copy_from_slice(&try_begin_disp.to_le_bytes());

                    let try_end_offset = xdata.len() as u32;
                    xdata.extend_from_slice(&[0u8; 4]);
                    xdata_relocs.push(PendingReloc {
                        offset: try_end_offset,
                        symbol: fn_sym_ix[fi] as u32,
                        kind: RelocKind::Addr32nb,
                    });
                    let last = xdata.len();
                    xdata[last - 4..last].copy_from_slice(&s.try_end.to_le_bytes());

                    let handler_offset = xdata.len() as u32;
                    xdata.extend_from_slice(&[0u8; 4]);
                    xdata_relocs.push(PendingReloc {
                        offset: handler_offset,
                        symbol: fn_sym_ix[fi] as u32,
                        kind: RelocKind::Addr32nb,
                    });
                    let last = xdata.len();
                    xdata[last - 4..last].copy_from_slice(&s.handler.to_le_bytes());

                    let (kind, _vt_rec) = match s.policy {
                        CatchPolicy::Int => (0u32, None),
                        CatchPolicy::ByRef { class_record_id } => (1u32, Some(class_record_id)),
                        CatchPolicy::ByPtr { class_record_id } => (2u32, Some(class_record_id)),
                        CatchPolicy::Cleanup => (3u32, None),
                        // catch-all: match any in-range exception, no typeinfo.
                        CatchPolicy::CatchAll => (4u32, None),
                    };
                    xdata.extend_from_slice(&kind.to_le_bytes());

                    // catch_type_rva: Addr32nb against the class vtable
                    // static for class-typed catches; zero for int /
                    // cleanup.
                    let catch_type_offset = xdata.len() as u32;
                    xdata.extend_from_slice(&[0u8; 4]);
                    let rec_id = match s.policy {
                        CatchPolicy::ByRef { class_record_id }
                        | CatchPolicy::ByPtr { class_record_id } => Some(class_record_id),
                        _ => None,
                    };
                    if let Some(rid) = rec_id {
                        // S4.2ae: catch_type_rva is the catch class's EH type
                        // tag — its VTABLE RVA when polymorphic, else its
                        // typeinfo-entry RVA (the entry-as-descriptor), exactly
                        // what throw stamps. The personality compares the two.
                        let catch_sym = if let Some(vt_ix) =
                            self.module.vtables.iter().position(|vt| vt.id == rid)
                        {
                            vtable_sym_ix[vt_ix]
                        } else if let Some(ti_ix) = self
                            .module
                            .typeinfo
                            .iter()
                            .position(|e| e.class_record_id == rid)
                        {
                            typeinfo_sym_ix[ti_ix]
                        } else {
                            panic!(
                                "S4.2ae: catch on record {rid} has neither a \
                                 vtable nor a typeinfo entry"
                            )
                        };
                        xdata_relocs.push(PendingReloc {
                            offset: catch_type_offset,
                            symbol: catch_sym as u32,
                            kind: RelocKind::Addr32nb,
                        });
                    }
                    let _ = xdata_section_sym;
                }
            }

            let _ = fi;
        }

        // Second pass: build .pdata now we know each fn's .xdata offset.
        for (fi, f) in self.module.funcs.iter().enumerate() {
            let Some(xdata_off) = fn_xdata_off[fi] else {
                continue;
            };
            // BeginAddress: Addr32nb against function sym, addend 0.
            let begin_offset = pdata.len() as u32;
            pdata.extend_from_slice(&[0u8; 4]);
            pdata_relocs.push(PendingReloc {
                offset: begin_offset,
                symbol: fn_sym_ix[fi] as u32,
                kind: RelocKind::Addr32nb,
            });

            // EndAddress: Addr32nb against function sym, addend =
            // function's code length.
            let end_offset = pdata.len() as u32;
            pdata.extend_from_slice(&[0u8; 4]);
            pdata_relocs.push(PendingReloc {
                offset: end_offset,
                symbol: fn_sym_ix[fi] as u32,
                kind: RelocKind::Addr32nb,
            });
            let last = pdata.len();
            let code_len = f.code.len() as u32;
            pdata[last - 4..last].copy_from_slice(&code_len.to_le_bytes());

            // UnwindInfoAddress: Addr32nb against .xdata section sym,
            // addend = fn_xdata_off[fi].
            let unwind_offset = pdata.len() as u32;
            pdata.extend_from_slice(&[0u8; 4]);
            pdata_relocs.push(PendingReloc {
                offset: unwind_offset,
                symbol: xdata_section_sym as u32,
                kind: RelocKind::Addr32nb,
            });
            let last = pdata.len();
            pdata[last - 4..last].copy_from_slice(&xdata_off.to_le_bytes());
        }

        (pdata, xdata)
    }

    /// Look up the symbol-table index of the section-def symbol for
    /// `kind`. Used by the EH plumbing to reference `.xdata` from
    /// `.pdata` via the section symbol (which is the standard COFF
    /// way to express "this RVA is at offset N inside this section").
    fn section_symbol_index_for(&self, kind: EmitSection) -> usize {
        // The section-def symbols are emitted at the START of
        // obj.symbols (one per emitted section, in section header
        // order). The order matches `section_kinds` in `emit_object`.
        // We replicate that ordering here.
        let mut ix = 0usize;
        let order = [
            (EmitSection::Text, !self.text_image.is_empty()),
            (EmitSection::Data, !self.data_image.is_empty()),
            (EmitSection::Rdata, !self.rdata_image.is_empty()),
            (
                EmitSection::Pdata,
                self.module.funcs.iter().any(|f| !f.try_scopes.is_empty()),
            ),
            (
                EmitSection::Xdata,
                self.module.funcs.iter().any(|f| !f.try_scopes.is_empty()),
            ),
        ];
        for (k, present) in order {
            if !present {
                continue;
            }
            if k == kind {
                return ix;
            }
            ix += 1;
        }
        // Caller asked for a non-emitted section's symbol — programmer
        // error. Personality-bearing TUs always emit .xdata, and the
        // EH path is the only caller asking for one today.
        panic!("S1b.4: section_symbol_index_for: {kind:?} is not emitted");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Section kinds the converter emits. Used to keep the emission order
/// deterministic and to look up per-section symbol indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EmitSection {
    Text,
    Data,
    Rdata,
    Pdata,
    Xdata,
}

impl EmitSection {
    fn canonical_section_name(self) -> &'static str {
        match self {
            EmitSection::Text => ".text",
            EmitSection::Data => ".data",
            EmitSection::Rdata => ".rdata",
            EmitSection::Pdata => ".pdata",
            EmitSection::Xdata => ".xdata",
        }
    }
}

/// Internal pending-reloc record used during the converter pass — kept
/// separate from `coff::Reloc` so we can build the list before the
/// symbol indices are stable, then materialise the final COFF relocs
/// in one swoop. The two are structurally identical today but the
/// indirection makes future "reloc with explicit addend" support
/// (S2 / 32-bit ABI) a single-line extension.
#[derive(Debug, Clone, Copy)]
struct PendingReloc {
    offset: u32,
    symbol: u32,
    kind: RelocKind,
}

impl PendingReloc {
    fn to_coff(self) -> Reloc {
        Reloc {
            offset: self.offset,
            symbol: self.symbol,
            kind: self.kind,
        }
    }
}

// ---------------------------------------------------------------------------
// UNWIND_INFO constants — duplicated from pe.rs to keep this module
// self-contained. The pe.rs originals are crate-private (`fn`-local
// scope), so a public re-export would be a wider change than this
// 6-line duplication.
// ---------------------------------------------------------------------------

const MDBCC_PROLOG_SIZE: u8 = 0x0B;
const MDBCC_PROLOG_PUSH_RBP_OFFSET: u8 = 0x01;
const MDBCC_PROLOG_SUB_RSP_OFFSET: u8 = 0x0B;
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_OPINFO_RBP: u8 = 5;
const UNW_FLAG_EHANDLER: u8 = 1;

/// Recover the `sub rsp, imm32` immediate from a function's prologue.
/// Same algorithm as `pe::read_prolog_alloc`, duplicated here to avoid
/// promoting it to a crate-public function (pe.rs is being retired
/// into mdlink in S1c per Q1; the converter shouldn't depend on it).
fn read_prolog_alloc(code: &[u8]) -> Result<u32, String> {
    if code.len() < MDBCC_PROLOG_SIZE as usize {
        return Err("function shorter than mdbcc prologue".into());
    }
    if code[0] != 0x55 || code[1..4] != [0x48, 0x89, 0xE5] || code[4..7] != [0x48, 0x81, 0xEC] {
        return Err("function prologue does not match expected push/mov/sub shape".into());
    }
    Ok(u32::from_le_bytes(code[7..11].try_into().unwrap()))
}

fn is_unwindless_thunk(f: &CompiledFn) -> bool {
    f.name.starts_with("$thunk$")
}
