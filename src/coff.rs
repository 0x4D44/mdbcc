//! S1b.2 — Pure COFF object writer skeleton (encoder + decoder + types).
//!
//! This module implements the `Object` IR described in HLD §1.2 and the
//! byte-level COFF encoding described in HLD §2 — for x86_64 today
//! (`IMAGE_FILE_MACHINE_AMD64 = 0x8664`); the `Machine::I386` variant is
//! reserved for S2 and is rejected by the encoder until that wiring lands.
//!
//! Nothing in mdbcc currently calls this module. S1b.4 will introduce
//! `compile_to_object` which produces an `Object` and serialises it via
//! [`Object::write`]; S1c (`mdlink`) will consume the bytes via
//! [`Object::read`]. Until then the contract is enforced exclusively by
//! `tests/coff_object_format.rs` (round-trip tests + a lld-link
//! format-conformance gate).
//!
//! ## Determinism (R16 — hard)
//!
//! Every byte emitted is a function of the input `Object` alone. No
//! wall-clock timestamps, no `HashMap` iteration into bytes, no
//! environment lookups. The internal `StringTable` keeps a `HashMap`
//! only as a dedup index — emission walks the owned `Vec<u8>` buffer.
//! Sections, symbols, relocations, and strings emit in the order they
//! appear in `Object`; the caller decides ordering and the encoder
//! preserves it.

#![allow(dead_code)]

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PE/COFF constants (Microsoft PE/COFF spec §3 — §5)
// ---------------------------------------------------------------------------

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// Mask covering every IMAGE_SCN_ALIGN_*BYTES bit pattern. Used in unit
/// tests to extract the alignment field from `characteristics`.
const IMAGE_SCN_ALIGN_MASK: u32 = 0x00F0_0000;

const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
const IMAGE_REL_AMD64_SECTION: u16 = 0x000A;
const IMAGE_REL_AMD64_SECREL: u16 = 0x000B;

// i386 relocation types (PE/COFF spec §5.2.2 — "x86 processors"). S2c
// added these alongside the AMD64 constants when `Object.machine ==
// I386` became a real serialisation target. The notable absence is any
// "ADDR64" equivalent: x86 has no 64-bit pointer, so emitting an
// `Addr64` reloc into an i386 object is a hard error (see
// `RelocKind::to_i386`).
const IMAGE_REL_I386_ABSOLUTE: u16 = 0x0000;
const IMAGE_REL_I386_DIR32: u16 = 0x0006;
const IMAGE_REL_I386_DIR32NB: u16 = 0x0007;
const IMAGE_REL_I386_SECTION: u16 = 0x000A;
const IMAGE_REL_I386_SECREL: u16 = 0x000B;
const IMAGE_REL_I386_REL32: u16 = 0x0014;

const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
const IMAGE_SYM_CLASS_STATIC: u8 = 3;
const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;

/// `IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_FUNCTION << 4)` — the only
/// non-zero Type value mdbcc emits. The Type field is a 16-bit LE value
/// in the symbol record at offset 14.
const IMAGE_SYM_TYPE_FUNCTION: u16 = 0x20;

const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const SYMBOL_SIZE: usize = 18;
const RELOC_SIZE: usize = 10;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One translation unit, COFF-shaped. Construct, populate, and feed to
/// [`Object::write`] to produce the on-disk `.obj` byte image.
#[derive(Debug, Clone, Default)]
pub struct Object {
    pub machine: Machine,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub strtab: StringTable,
    /// `.drectve` raw bytes. When non-empty the encoder synthesises a
    /// `.drectve` section automatically (the caller does not push one).
    pub directives: Vec<u8>,
    /// J-8b (tick 74) source-loc threading for diagnostics. Parallel to
    /// `symbols`; each entry is `Some((line, col))` when the symbol was
    /// introduced by a code construct with a known source position (a
    /// call to an undefined external is the common case — the loc lets
    /// `LinkError::UnresolvedExternals` render `"line:col: unresolved
    /// external function 'X'"` matching the legacy `pe::build_text`
    /// diagnostic). `None` for synthetic / converter-generated symbols
    /// (section symbols, statics, defined externals). Not on-wire — the
    /// COFF encoder/decoder ignore this field; round-tripping a `.obj`
    /// through `Object::write` + `Object::read` resets every entry to
    /// `None` (which is fine; the multi-file linker reads .obj bytes
    /// from disk and never had the original Loc info anyway).
    pub symbol_source_locs: Vec<Option<(u32, u32)>>,
}

/// Target machine. `Amd64` is the only encoded value today; `I386` is
/// reserved for S2 and rejected by the encoder until S2 wiring lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Machine {
    #[default]
    Amd64,
    I386,
}

/// A COFF section. `data` carries the raw bytes; `relocs` references
/// symbols by 0-based index into `Object::symbols` (the encoder maps the
/// index to a 1-based aux-aware symbol-table position automatically —
/// see [`Object::write`]).
#[derive(Debug, Clone)]
pub struct Section {
    pub name: SectionName,
    pub data: Vec<u8>,
    /// Size for `.bss` (uninitialised) sections. Ignored when `data` is
    /// non-empty.
    pub bss_size: u32,
    pub relocs: Vec<Reloc>,
    pub characteristics: u32,
    pub comdat: Option<Comdat>,
}

impl Section {
    /// Convenience: a fresh `.text` section with the canonical
    /// IMAGE_SCN_CNT_CODE | EXECUTE | READ | ALIGN_16 characteristics.
    pub fn text() -> Self {
        Self {
            name: SectionName::Text,
            data: Vec::new(),
            bss_size: 0,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_CNT_CODE
                | IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_ALIGN_16BYTES,
            comdat: None,
        }
    }
    /// Convenience: a fresh `.data` section.
    pub fn data() -> Self {
        Self {
            name: SectionName::Data,
            data: Vec::new(),
            bss_size: 0,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE
                | IMAGE_SCN_ALIGN_8BYTES,
            comdat: None,
        }
    }
    /// Convenience: a fresh `.rdata` section.
    pub fn rdata() -> Self {
        Self {
            name: SectionName::Rdata,
            data: Vec::new(),
            bss_size: 0,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_ALIGN_8BYTES,
            comdat: None,
        }
    }
    /// Convenience: a fresh `.bss` section sized to `n` bytes.
    pub fn bss(n: u32) -> Self {
        Self {
            name: SectionName::Bss,
            data: Vec::new(),
            bss_size: n,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_CNT_UNINITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE
                | IMAGE_SCN_ALIGN_8BYTES,
            comdat: None,
        }
    }
    /// Convenience: a fresh `.pdata` section.
    pub fn pdata() -> Self {
        Self {
            name: SectionName::Pdata,
            data: Vec::new(),
            bss_size: 0,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_ALIGN_4BYTES,
            comdat: None,
        }
    }
    /// Convenience: a fresh `.xdata` section.
    pub fn xdata() -> Self {
        Self {
            name: SectionName::Xdata,
            data: Vec::new(),
            bss_size: 0,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_ALIGN_4BYTES,
            comdat: None,
        }
    }
    /// Convenience: a fresh `.drectve` section with the canonical
    /// LNK_INFO | LNK_REMOVE flags and the supplied bytes.
    pub fn drectve(bytes: Vec<u8>) -> Self {
        Self {
            name: SectionName::Drectve,
            data: bytes,
            bss_size: 0,
            relocs: Vec::new(),
            characteristics: IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE,
            comdat: None,
        }
    }

    /// The raw-data length the section contributes to the file
    /// (initialised data only; `.bss` reports 0).
    fn raw_size(&self) -> u32 {
        if self.is_bss() {
            0
        } else {
            self.data.len() as u32
        }
    }
    /// The logical section size (VirtualSize-equivalent — for object files
    /// the field is `PhysicalAddress` but encoders use it as the
    /// VirtualSize for `.bss`).
    fn virt_size(&self) -> u32 {
        if self.is_bss() {
            self.bss_size
        } else {
            self.data.len() as u32
        }
    }
    fn is_bss(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }
}

/// Section name, either a canonical kind (encoded as a fixed string) or
/// a COMDAT-qualified variant carrying the merge discriminator. The
/// encoder writes the rendered name into the 8-byte header slot — or,
/// if longer than 8 bytes, into the string table with the slot
/// encoding `[0,0,0,0, offset_le_u32]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionName {
    Text,
    Data,
    Bss,
    Rdata,
    Pdata,
    Xdata,
    Drectve,
    /// `.text$<sym>` — per-COMDAT-function text.
    TextComdat(String),
    /// `.rdata$<sym>` — per-COMDAT rdata (vtables, typeinfo).
    RdataComdat(String),
    /// `.xdata$<sym>` — per-COMDAT EH info (associative to text).
    XdataComdat(String),
    /// `.pdata$<sym>` — per-COMDAT pdata (associative to text).
    PdataComdat(String),
    /// Escape hatch for any other section name the front-end needs to
    /// emit literally (e.g. `.rdata$xt$<class>`, `.CRT$XCU`). The string
    /// is used verbatim; characters outside the COFF section-name set
    /// are passed through.
    Custom(String),
}

impl SectionName {
    pub fn as_str(&self) -> &str {
        // Returns a non-owning view. For COMDAT variants we cannot return
        // a single &str (the prefix and the discriminator are in two
        // pieces), so callers that need the full literal name go through
        // [`SectionName::render`].
        match self {
            SectionName::Text => ".text",
            SectionName::Data => ".data",
            SectionName::Bss => ".bss",
            SectionName::Rdata => ".rdata",
            SectionName::Pdata => ".pdata",
            SectionName::Xdata => ".xdata",
            SectionName::Drectve => ".drectve",
            SectionName::TextComdat(_) => ".text$",
            SectionName::RdataComdat(_) => ".rdata$",
            SectionName::XdataComdat(_) => ".xdata$",
            SectionName::PdataComdat(_) => ".pdata$",
            SectionName::Custom(s) => s.as_str(),
        }
    }

    /// Render the full literal name as a `String` — joins COMDAT prefix
    /// and discriminator for the `*Comdat` variants.
    pub fn render(&self) -> String {
        match self {
            SectionName::TextComdat(s) => format!(".text${s}"),
            SectionName::RdataComdat(s) => format!(".rdata${s}"),
            SectionName::XdataComdat(s) => format!(".xdata${s}"),
            SectionName::PdataComdat(s) => format!(".pdata${s}"),
            _ => self.as_str().to_string(),
        }
    }

    /// Encode the section name into the 8-byte header slot. If the
    /// rendered name fits inline (`len() <= 8`) it is copied directly,
    /// padded with zeros. Otherwise the name is interned into `st` and
    /// the slot encodes `[/<decimal_offset>]` per the COFF section-name
    /// long-name convention (NOT the same as the symbol-name long form;
    /// section long names use ASCII decimal, written into the 8-byte
    /// slot as `'/'` followed by the offset decimal-digits, padded with
    /// zeros).
    pub fn encode_to_strtab(&self, st: &mut StringTable) -> [u8; 8] {
        let name = self.render();
        encode_section_name_slot(&name, st)
    }
}

/// Helper exposed so `Object::write` and tests share one implementation
/// of the section-name slot encoding.
fn encode_section_name_slot(name: &str, st: &mut StringTable) -> [u8; 8] {
    let mut out = [0u8; 8];
    let bytes = name.as_bytes();
    if bytes.len() <= 8 {
        out[..bytes.len()].copy_from_slice(bytes);
        return out;
    }
    // Long section name: `/<decimal_offset>` ASCII into the 8-byte slot.
    // PE/COFF spec §3 (object files, section headers) defines this form
    // — note that symbol-name long form uses a different encoding (4
    // zero bytes + u32 offset), so the two are not interchangeable.
    let off = st.intern(name);
    let s = format!("/{off}");
    let sb = s.as_bytes();
    if sb.len() > 8 {
        // Pathologically long strtab — fall back to the longest prefix
        // that fits. mdbcc never produces strtabs > ~16 MB so this
        // branch is academic; document it for future me.
        out.copy_from_slice(&sb[..8]);
    } else {
        out[..sb.len()].copy_from_slice(sb);
    }
    out
}

/// COMDAT descriptor attached to a section header. The `selection`
/// drives the linker's dedup behaviour; `Associative` carries an
/// associated section's 1-based index in `associated_section`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comdat {
    pub selection: ComdatSelect,
    /// 1-based index of the associated section, when `selection ==
    /// Associative`. Ignored for other selections.
    pub associated_section: u16,
}

/// COMDAT selection codes (PE/COFF spec §5.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComdatSelect {
    NoDuplicates = 1,
    Any = 2,
    SameSize = 3,
    ExactMatch = 4,
    Associative = 5,
    Largest = 6,
}

impl ComdatSelect {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ComdatSelect::NoDuplicates),
            2 => Some(ComdatSelect::Any),
            3 => Some(ComdatSelect::SameSize),
            4 => Some(ComdatSelect::ExactMatch),
            5 => Some(ComdatSelect::Associative),
            6 => Some(ComdatSelect::Largest),
            _ => None,
        }
    }
}

/// One relocation. `symbol` is the 0-based index into `Object::symbols`
/// (the encoder converts to the COFF on-disk symbol-table index, which
/// counts aux records too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    pub offset: u32,
    pub symbol: u32,
    pub kind: RelocKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// `IMAGE_REL_AMD64_ADDR64` — absolute 64-bit VA.
    Addr64,
    /// `IMAGE_REL_AMD64_ADDR32` — absolute 32-bit VA. Rare in x64.
    Addr32,
    /// `IMAGE_REL_AMD64_ADDR32NB` — 32-bit RVA (no base).
    Addr32nb,
    /// `IMAGE_REL_AMD64_REL32` — 32-bit relative.
    Rel32,
    /// `IMAGE_REL_AMD64_SECTION` — 16-bit section index (debug info).
    SectionIx,
    /// `IMAGE_REL_AMD64_SECREL` — 32-bit section-relative offset (debug).
    SecRel32,
}

impl RelocKind {
    /// Encode this logical reloc kind to its on-wire `Type` field for
    /// the supplied `machine`. Routes per HLD §4.1: AMD64 keeps its
    /// historical mapping; i386 maps to the `IMAGE_REL_I386_*` family
    /// and rejects `Addr64` (x86 has no 64-bit pointer reloc).
    pub(crate) fn to_wire(self, machine: Machine) -> Result<u16, CoffError> {
        match machine {
            Machine::Amd64 => Ok(self.to_amd64()),
            Machine::I386 => self.to_i386(),
        }
    }
    /// Decode an on-wire `Type` field back to a logical reloc kind for
    /// the supplied `machine`. The inverse of `to_wire`.
    pub(crate) fn from_wire(v: u16, machine: Machine) -> Option<Self> {
        match machine {
            Machine::Amd64 => Self::from_amd64(v),
            Machine::I386 => Self::from_i386(v),
        }
    }
    fn to_amd64(self) -> u16 {
        match self {
            RelocKind::Addr64 => IMAGE_REL_AMD64_ADDR64,
            RelocKind::Addr32 => IMAGE_REL_AMD64_ADDR32,
            RelocKind::Addr32nb => IMAGE_REL_AMD64_ADDR32NB,
            RelocKind::Rel32 => IMAGE_REL_AMD64_REL32,
            RelocKind::SectionIx => IMAGE_REL_AMD64_SECTION,
            RelocKind::SecRel32 => IMAGE_REL_AMD64_SECREL,
        }
    }
    fn from_amd64(v: u16) -> Option<Self> {
        match v {
            IMAGE_REL_AMD64_ADDR64 => Some(RelocKind::Addr64),
            IMAGE_REL_AMD64_ADDR32 => Some(RelocKind::Addr32),
            IMAGE_REL_AMD64_ADDR32NB => Some(RelocKind::Addr32nb),
            IMAGE_REL_AMD64_REL32 => Some(RelocKind::Rel32),
            IMAGE_REL_AMD64_SECTION => Some(RelocKind::SectionIx),
            IMAGE_REL_AMD64_SECREL => Some(RelocKind::SecRel32),
            _ => None,
        }
    }
    /// i386 wire encoding per HLD §4.1. `Addr64` has no i386 equivalent
    /// — x86 has no 64-bit pointer reloc — and is rejected explicitly.
    fn to_i386(self) -> Result<u16, CoffError> {
        match self {
            RelocKind::Addr64 => Err(CoffError::RelocKindUnsupported(self, Machine::I386)),
            RelocKind::Addr32 => Ok(IMAGE_REL_I386_DIR32),
            RelocKind::Addr32nb => Ok(IMAGE_REL_I386_DIR32NB),
            RelocKind::Rel32 => Ok(IMAGE_REL_I386_REL32),
            RelocKind::SectionIx => Ok(IMAGE_REL_I386_SECTION),
            RelocKind::SecRel32 => Ok(IMAGE_REL_I386_SECREL),
        }
    }
    fn from_i386(v: u16) -> Option<Self> {
        match v {
            IMAGE_REL_I386_DIR32 => Some(RelocKind::Addr32),
            IMAGE_REL_I386_DIR32NB => Some(RelocKind::Addr32nb),
            IMAGE_REL_I386_REL32 => Some(RelocKind::Rel32),
            IMAGE_REL_I386_SECTION => Some(RelocKind::SectionIx),
            IMAGE_REL_I386_SECREL => Some(RelocKind::SecRel32),
            _ => None,
        }
    }
}

/// One COFF symbol-table entry plus its (optional) auxiliary records.
/// `aux` records emit immediately after the main entry — the encoder
/// computes `NumberOfAuxSymbols` automatically from `aux.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: SymName,
    pub value: u32,
    pub section: SectionRef,
    pub kind: SymKind,
    pub storage: StorageClass,
    pub aux: Vec<AuxRecord>,
}

/// The 8-byte symbol name slot. `Short` is up to 8 bytes inline (padded
/// with zeros); `Long` is a 4-byte LE offset into the string table
/// preceded by 4 zero bytes (the symbol-name long form; distinct from
/// the section-name long form which uses `/<decimal>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymName {
    Short([u8; 8]),
    Long(u32),
}

impl SymName {
    /// Construct from a `&str`, automatically picking `Short` when the
    /// name fits inline. `st` is consulted to dedup interning; passing
    /// the same name twice yields the same offset.
    pub fn from_str(s: &str, st: &mut StringTable) -> Self {
        let b = s.as_bytes();
        if b.len() <= 8 {
            let mut a = [0u8; 8];
            a[..b.len()].copy_from_slice(b);
            SymName::Short(a)
        } else {
            SymName::Long(st.intern(s))
        }
    }
}

/// Reference to a section by number, or one of the three reserved
/// pseudo-section values. The encoder writes the 1-based section number
/// (the +1 offset is applied automatically; callers pass 1-based as
/// well — the value matches what `dumpbin /symbols` reports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionRef {
    /// 1-based section index.
    Section(u16),
    /// SectionNumber = 0 — undefined (external reference).
    Undefined,
    /// SectionNumber = -1 — absolute (immediate value).
    Absolute,
    /// SectionNumber = -2 — debug (compiler-emitted).
    Debug,
}

impl SectionRef {
    fn to_i16(self) -> i16 {
        match self {
            SectionRef::Section(n) => n as i16,
            SectionRef::Undefined => 0,
            SectionRef::Absolute => -1,
            SectionRef::Debug => -2,
        }
    }
    fn from_i16(v: i16) -> Self {
        match v {
            0 => SectionRef::Undefined,
            -1 => SectionRef::Absolute,
            -2 => SectionRef::Debug,
            n if n > 0 => SectionRef::Section(n as u16),
            _ => SectionRef::Section(0),
        }
    }
}

/// Symbol kind. `Function` sets the high nibble of the Type field
/// (`IMAGE_SYM_DTYPE_FUNCTION`); `Notype` leaves it zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymKind {
    Function,
    Notype,
}

impl SymKind {
    fn to_type(self) -> u16 {
        match self {
            SymKind::Function => IMAGE_SYM_TYPE_FUNCTION,
            SymKind::Notype => 0,
        }
    }
    fn from_type(v: u16) -> Self {
        if v == IMAGE_SYM_TYPE_FUNCTION {
            SymKind::Function
        } else {
            SymKind::Notype
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    External,
    Static,
    WeakExternal,
}

impl StorageClass {
    fn to_u8(self) -> u8 {
        match self {
            StorageClass::External => IMAGE_SYM_CLASS_EXTERNAL,
            StorageClass::Static => IMAGE_SYM_CLASS_STATIC,
            StorageClass::WeakExternal => IMAGE_SYM_CLASS_WEAK_EXTERNAL,
        }
    }
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            IMAGE_SYM_CLASS_EXTERNAL => Some(StorageClass::External),
            IMAGE_SYM_CLASS_STATIC => Some(StorageClass::Static),
            IMAGE_SYM_CLASS_WEAK_EXTERNAL => Some(StorageClass::WeakExternal),
            _ => None,
        }
    }
}

/// Auxiliary symbol-table records. PE/COFF defines five formats; mdbcc
/// uses two: Format 5 (Section Definition — attached to each STATIC
/// section symbol) and Format 3 (Weak External — for inline-function-
/// style fold semantics). File/FunctionDef aux records are deferred to
/// the debug-info work (S8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuxRecord {
    /// Aux Format 5 — Section Definition. Carries the section's length,
    /// relocation count, checksum, and (for COMDATs) the associated
    /// section number + selection code.
    SectionDef {
        length: u32,
        num_relocs: u16,
        checksum: u32,
        /// For `Selection::Associative`, the 1-based section index this
        /// COMDAT is associated with. Zero for non-COMDAT sections.
        number: u16,
        /// COMDAT selection code. `None` for non-COMDAT section symbols
        /// (encoded as zero).
        selection: Option<ComdatSelect>,
    },
    /// Aux Format 3 — Weak External. `tag` is the symbol-table index of
    /// the default symbol; `characteristics` is one of the
    /// `IMAGE_WEAK_EXTERN_SEARCH_*` codes.
    WeakExtern { tag: u32, characteristics: u32 },
}

// ---------------------------------------------------------------------------
// String table
// ---------------------------------------------------------------------------

/// COFF string table — owned `Vec<u8>` plus a dedup index that is NOT
/// part of the emitted bytes. The string table emits as a 4-byte LE
/// size prefix (the size INCLUDES the prefix itself) followed by the
/// concatenated null-terminated names. The first valid offset for a
/// name is therefore `4`; the encoder reserves it for the size field.
#[derive(Debug, Clone, Default)]
pub struct StringTable {
    /// Raw bytes from offset 4 onwards — the size prefix is computed
    /// at emission time. Each interned name is followed by `\0`.
    bytes: Vec<u8>,
    /// Dedup lookup. Insertion-order iteration is irrelevant because
    /// emission walks `bytes`, not this map.
    index: HashMap<String, u32>,
}

impl StringTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern `s`. Returns the 4-byte offset within the strtab at which
    /// the name's first byte begins (i.e. `4 + position_in_bytes`).
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&off) = self.index.get(s) {
            return off;
        }
        let off = 4 + self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        self.index.insert(s.to_string(), off);
        off
    }

    /// Resolve an offset (as returned by `intern`) back to the original
    /// bytes. Returns `None` for malformed / out-of-range offsets.
    pub fn get(&self, offset: u32) -> Option<&[u8]> {
        if offset < 4 {
            return None;
        }
        let start = (offset - 4) as usize;
        if start >= self.bytes.len() {
            return None;
        }
        let end = self.bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|n| start + n)?;
        Some(&self.bytes[start..end])
    }

    /// Resolve an offset to UTF-8. Returns `None` on malformed UTF-8.
    pub fn get_str(&self, offset: u32) -> Option<&str> {
        std::str::from_utf8(self.get(offset)?).ok()
    }

    /// Total size of the emitted string-table image (size prefix + body).
    pub fn emit_size(&self) -> u32 {
        4 + self.bytes.len() as u32
    }

    /// Emit the strtab bytes: 4-byte LE size prefix (inclusive) followed
    /// by the body.
    pub fn finalize(&self) -> Vec<u8> {
        let total = self.emit_size();
        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Reconstruct a `StringTable` from raw on-disk bytes (the 4-byte
    /// size prefix + body). The dedup index is rebuilt by scanning.
    fn from_bytes(raw: &[u8]) -> Result<Self, CoffError> {
        if raw.len() < 4 {
            return Err(CoffError::Truncated);
        }
        let declared = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if declared > raw.len() {
            return Err(CoffError::Truncated);
        }
        let body_end = declared.max(4);
        let bytes = raw[4..body_end].to_vec();
        let mut index = HashMap::new();
        let mut start = 0usize;
        while start < bytes.len() {
            let end = match bytes[start..].iter().position(|&b| b == 0) {
                Some(n) => start + n,
                None => break,
            };
            if end > start
                && let Ok(s) = std::str::from_utf8(&bytes[start..end])
            {
                index.entry(s.to_string()).or_insert(4 + start as u32);
            }
            start = end + 1;
        }
        Ok(StringTable { bytes, index })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoffError {
    Truncated,
    BadMachine(u16),
    BadSectionCount(u16),
    BadAuxCount,
    BadStringOffset(u32),
    BadSymbolName,
    /// Wire-level reloc `Type` field did not decode to a known
    /// `RelocKind`. Carries both the raw value and the machine the
    /// decoder was operating in, so the diagnostic can tell the user
    /// which encoding family it tried (AMD64 vs i386).
    BadRelocKind(u16, Machine),
    BadStorageClass(u8),
    BadComdatSelection(u8),
    BadSectionName,
    UnsupportedMachine(Machine),
    /// Caller asked the encoder to serialise a `RelocKind` that has no
    /// representation on the target machine — currently
    /// `RelocKind::Addr64` on `Machine::I386`. Raised by
    /// `RelocKind::to_wire` and surfaced through `Object::write` (which
    /// today still emits via `to_wire().unwrap()` because the existing
    /// AMD64 path is total; the i386 path debug-asserts on misuse).
    RelocKindUnsupported(RelocKind, Machine),
}

impl std::fmt::Display for CoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoffError::Truncated => write!(f, "COFF file truncated"),
            CoffError::BadMachine(m) => write!(f, "unknown COFF machine 0x{m:04x}"),
            CoffError::BadSectionCount(n) => write!(f, "implausible section count {n}"),
            CoffError::BadAuxCount => write!(f, "aux record count mismatch"),
            CoffError::BadStringOffset(o) => write!(f, "string-table offset {o} out of range"),
            CoffError::BadSymbolName => write!(f, "bad symbol name encoding"),
            CoffError::BadRelocKind(v, m) => {
                write!(f, "unknown {m:?} relocation type 0x{v:04x}")
            }
            CoffError::BadStorageClass(v) => write!(f, "unknown storage class {v}"),
            CoffError::BadComdatSelection(v) => write!(f, "unknown COMDAT selection {v}"),
            CoffError::BadSectionName => write!(f, "bad section name encoding"),
            CoffError::UnsupportedMachine(m) => write!(f, "unsupported machine {m:?}"),
            CoffError::RelocKindUnsupported(k, m) => {
                write!(f, "relocation kind {k:?} not supported on {m:?}")
            }
        }
    }
}

impl std::error::Error for CoffError {}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

impl Object {
    /// Serialise to COFF bytes. Two-pass: pass 1 plans layout and
    /// computes file offsets; pass 2 streams bytes. The strtab is
    /// finalised at the end of pass 1 so name interning during section-
    /// name encoding sees a stable view.
    ///
    /// Determinism: every byte emitted is a pure function of `self`.
    pub fn write(&self) -> Vec<u8> {
        // We work on a clone of the strtab because section-name encoding
        // may intern long section names. Callers should not observe
        // strtab mutation from a `write()` call.
        let mut strtab = self.strtab.clone();

        // Synthesise a .drectve section when `directives` is non-empty
        // and the caller has not pushed one explicitly. The synthesised
        // section is appended; its index is therefore predictable.
        let mut effective_sections: Vec<Section> = self.sections.clone();
        if !self.directives.is_empty()
            && !effective_sections
                .iter()
                .any(|s| matches!(s.name, SectionName::Drectve))
        {
            effective_sections.push(Section::drectve(self.directives.clone()));
        }

        // Pass 1: precompute per-section offsets and the rendered name slots.
        let n_sec = effective_sections.len();
        let mut name_slots: Vec<[u8; 8]> = Vec::with_capacity(n_sec);
        for sec in &effective_sections {
            name_slots.push(sec.name.encode_to_strtab(&mut strtab));
        }

        // Layout: header | section headers | section data | relocs | symbols | strtab
        let headers_end = FILE_HEADER_SIZE + n_sec * SECTION_HEADER_SIZE;
        // Section data offsets — only initialised data sections occupy
        // file bytes. `.bss` reports SizeOfRawData=0 and
        // PointerToRawData=0 (per the spec for uninitialised sections).
        let mut sec_data_off: Vec<u32> = vec![0; n_sec];
        let mut cursor = headers_end as u32;
        for (i, sec) in effective_sections.iter().enumerate() {
            if sec.is_bss() {
                sec_data_off[i] = 0;
            } else {
                sec_data_off[i] = cursor;
                cursor += sec.raw_size();
            }
        }
        // Relocation table offsets — packed after all section data.
        let mut sec_reloc_off: Vec<u32> = vec![0; n_sec];
        for (i, sec) in effective_sections.iter().enumerate() {
            if !sec.relocs.is_empty() {
                sec_reloc_off[i] = cursor;
                cursor += (sec.relocs.len() as u32) * RELOC_SIZE as u32;
            }
        }
        let sym_table_off = cursor;
        let total_sym_entries: usize = self.symbols.iter().map(|s| 1 + s.aux.len()).sum();
        cursor += (total_sym_entries as u32) * SYMBOL_SIZE as u32;
        // Now we know the symbol-table extent, but the strtab will only
        // be finalised after we serialise symbol entries (each long
        // name may intern into it). Long symbol names are interned NOW
        // so the strtab size is fixed for the file header layout but —
        // since strtab is only referenced by offset, not by file
        // position — we don't actually need a strtab offset in the
        // file header. We just write the strtab at `cursor`.

        // Precompute symbol name slots (interning into strtab now so
        // emit reads a stable view).
        let sym_name_slots: Vec<[u8; 8]> = self
            .symbols
            .iter()
            .map(|s| match &s.name {
                SymName::Short(a) => *a,
                SymName::Long(off) => long_name_slot(*off),
            })
            .collect();

        // Map from user-supplied 0-based symbol index → the 0-based
        // index within the *flattened* on-disk symbol table (counting
        // aux records). The encoder maps reloc.symbol through this.
        let mut sym_disk_ix: Vec<u32> = Vec::with_capacity(self.symbols.len());
        let mut k: u32 = 0;
        for sym in &self.symbols {
            sym_disk_ix.push(k);
            k += 1 + sym.aux.len() as u32;
        }

        // Pass 2: emit.
        let mut out: Vec<u8> = Vec::with_capacity(cursor as usize + strtab.emit_size() as usize);

        // IMAGE_FILE_HEADER (20 bytes).
        write_u16(&mut out, machine_to_u16(self.machine));
        write_u16(&mut out, n_sec as u16);
        write_u32(&mut out, 0); // TimeDateStamp — always zero (R16).
        write_u32(&mut out, sym_table_off);
        write_u32(&mut out, total_sym_entries as u32);
        write_u16(&mut out, 0); // SizeOfOptionalHeader — none in object files.
        write_u16(&mut out, 0); // Characteristics — none for object files.
        debug_assert_eq!(out.len(), FILE_HEADER_SIZE);

        // IMAGE_SECTION_HEADER * N (40 bytes each).
        for (i, sec) in effective_sections.iter().enumerate() {
            out.extend_from_slice(&name_slots[i]);
            // PhysicalAddress (treated as VirtualSize by linkers for
            // .bss; zero otherwise per Microsoft toolchain convention).
            let virt_size = if sec.is_bss() { sec.virt_size() } else { 0 };
            write_u32(&mut out, virt_size);
            write_u32(&mut out, 0); // VirtualAddress — zero in object files.
            write_u32(&mut out, sec.raw_size());
            write_u32(&mut out, sec_data_off[i]);
            write_u32(&mut out, sec_reloc_off[i]);
            write_u32(&mut out, 0); // PointerToLinenumbers.
            write_u16(&mut out, sec.relocs.len() as u16);
            write_u16(&mut out, 0); // NumberOfLinenumbers.
            // COMDAT bit: when the section carries a Comdat record we
            // force IMAGE_SCN_LNK_COMDAT on; otherwise we trust the
            // caller's characteristics verbatim.
            let chars = if sec.comdat.is_some() {
                sec.characteristics | IMAGE_SCN_LNK_COMDAT
            } else {
                sec.characteristics
            };
            write_u32(&mut out, chars);
        }

        // Section data (initialised data only).
        for sec in &effective_sections {
            if !sec.is_bss() {
                out.extend_from_slice(&sec.data);
            }
        }

        // Relocations per section. The wire encoding is target-
        // specific: on AMD64 every `RelocKind` maps; on i386 `Addr64`
        // is rejected by `to_wire` (no x86 equivalent — HLD §4.1).
        // We use `expect()` here because the converter is expected
        // to construct only target-valid relocations; reaching the
        // panic indicates a bug upstream in `codegen::object`.
        for sec in &effective_sections {
            for r in &sec.relocs {
                write_u32(&mut out, r.offset);
                // Map user index → disk index.
                let disk_ix = sym_disk_ix.get(r.symbol as usize).copied().unwrap_or(0);
                write_u32(&mut out, disk_ix);
                let wire = r
                    .kind
                    .to_wire(self.machine)
                    .expect("RelocKind incompatible with Object.machine");
                write_u16(&mut out, wire);
            }
        }
        debug_assert_eq!(out.len() as u32, sym_table_off);

        // Symbol table.
        for (i, sym) in self.symbols.iter().enumerate() {
            out.extend_from_slice(&sym_name_slots[i]);
            write_u32(&mut out, sym.value);
            write_i16(&mut out, sym.section.to_i16());
            write_u16(&mut out, sym.kind.to_type());
            out.push(sym.storage.to_u8());
            out.push(sym.aux.len() as u8);
            for aux in &sym.aux {
                write_aux(&mut out, aux);
            }
        }

        // String table.
        out.extend_from_slice(&strtab.finalize());

        out
    }
}

fn machine_to_u16(m: Machine) -> u16 {
    match m {
        Machine::Amd64 => IMAGE_FILE_MACHINE_AMD64,
        Machine::I386 => IMAGE_FILE_MACHINE_I386,
    }
}

fn machine_from_u16(v: u16) -> Option<Machine> {
    match v {
        IMAGE_FILE_MACHINE_AMD64 => Some(Machine::Amd64),
        IMAGE_FILE_MACHINE_I386 => Some(Machine::I386),
        _ => None,
    }
}

/// 8-byte slot for a long symbol name: 4 zero bytes followed by the
/// strtab offset as a 4-byte LE u32.
fn long_name_slot(offset: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[4..8].copy_from_slice(&offset.to_le_bytes());
    out
}

fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_i16(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn write_aux(out: &mut Vec<u8>, aux: &AuxRecord) {
    match *aux {
        AuxRecord::SectionDef {
            length,
            num_relocs,
            checksum,
            number,
            selection,
        } => {
            write_u32(out, length);
            write_u16(out, num_relocs);
            write_u16(out, 0); // NumberOfLinenumbers.
            write_u32(out, checksum);
            write_u16(out, number);
            out.push(match selection {
                Some(s) => s as u8,
                None => 0,
            });
            // 3 bytes unused.
            out.extend_from_slice(&[0u8; 3]);
        }
        AuxRecord::WeakExtern {
            tag,
            characteristics,
        } => {
            write_u32(out, tag);
            write_u32(out, characteristics);
            // 10 bytes unused.
            out.extend_from_slice(&[0u8; 10]);
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

impl Object {
    /// Decode a COFF byte image into an `Object`. Returns
    /// [`CoffError`] for any structural issue. Decoded relocations
    /// re-map disk symbol indices back to user-level (pre-aux)
    /// indices, so round-trips preserve `Reloc::symbol` values.
    pub fn read(bytes: &[u8]) -> Result<Object, CoffError> {
        if bytes.len() < FILE_HEADER_SIZE {
            return Err(CoffError::Truncated);
        }
        let machine_raw = u16::from_le_bytes([bytes[0], bytes[1]]);
        let machine = machine_from_u16(machine_raw).ok_or(CoffError::BadMachine(machine_raw))?;
        let num_sections = u16::from_le_bytes([bytes[2], bytes[3]]);
        // No hard upper bound in the spec, but a sanity bound helps
        // surface garbled inputs early. mdbcc emits a handful of
        // sections per TU; 65535 is the COFF on-disk limit.
        if num_sections == 0 && bytes.len() == FILE_HEADER_SIZE {
            // Plausible empty object — fall through.
        } else if num_sections as usize * SECTION_HEADER_SIZE + FILE_HEADER_SIZE > bytes.len() {
            return Err(CoffError::BadSectionCount(num_sections));
        }
        let _timestamp = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let sym_table_off = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let num_symbols = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        // Skip SizeOfOptionalHeader (u16) and Characteristics (u16);
        // for objects they are zero.

        // Locate the string table — it sits immediately after the
        // symbol table.
        let strtab_off = sym_table_off + num_symbols * SYMBOL_SIZE;
        let strtab = if strtab_off + 4 <= bytes.len() {
            let raw = &bytes[strtab_off..];
            let declared = if raw.len() >= 4 {
                u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize
            } else {
                0
            };
            let upper = strtab_off + declared.max(4).min(bytes.len() - strtab_off);
            StringTable::from_bytes(&bytes[strtab_off..upper.max(strtab_off + 4)])?
        } else {
            StringTable::default()
        };

        // Read section headers, then their data + relocs.
        let mut sections: Vec<Section> = Vec::with_capacity(num_sections as usize);
        for i in 0..num_sections as usize {
            let off = FILE_HEADER_SIZE + i * SECTION_HEADER_SIZE;
            if off + SECTION_HEADER_SIZE > bytes.len() {
                return Err(CoffError::Truncated);
            }
            let hdr = &bytes[off..off + SECTION_HEADER_SIZE];
            let name_slot: [u8; 8] = hdr[0..8].try_into().unwrap();
            let name_str = decode_section_name_slot(&name_slot, &strtab)?;
            let virt_size = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
            let raw_size = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
            let raw_off = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]) as usize;
            let reloc_off = u32::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]) as usize;
            let num_relocs = u16::from_le_bytes([hdr[32], hdr[33]]);
            let characteristics = u32::from_le_bytes([hdr[36], hdr[37], hdr[38], hdr[39]]);
            let is_bss = characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
            let data = if is_bss || raw_size == 0 {
                Vec::new()
            } else {
                if raw_off + raw_size as usize > bytes.len() {
                    return Err(CoffError::Truncated);
                }
                bytes[raw_off..raw_off + raw_size as usize].to_vec()
            };
            let mut relocs: Vec<Reloc> = Vec::with_capacity(num_relocs as usize);
            for r in 0..num_relocs as usize {
                let ro = reloc_off + r * RELOC_SIZE;
                if ro + RELOC_SIZE > bytes.len() {
                    return Err(CoffError::Truncated);
                }
                let rec = &bytes[ro..ro + RELOC_SIZE];
                let offset = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                let sym_disk = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                let kind_raw = u16::from_le_bytes([rec[8], rec[9]]);
                let kind = RelocKind::from_wire(kind_raw, machine)
                    .ok_or(CoffError::BadRelocKind(kind_raw, machine))?;
                relocs.push(Reloc {
                    offset,
                    symbol: sym_disk, // remapped after symbol-table read below
                    kind,
                });
            }
            let bss_size = if is_bss { virt_size } else { 0 };
            sections.push(Section {
                name: parse_section_name(&name_str)?,
                data,
                bss_size,
                relocs,
                characteristics,
                comdat: None, // populated after symbol decode (Aux Format 5)
            });
        }

        // Symbol-table read. We collect (sym, disk_index) so we can
        // later remap relocation symbol indices from disk → user form.
        let mut symbols: Vec<Symbol> = Vec::new();
        let mut disk_to_user: Vec<u32> = Vec::with_capacity(num_symbols);
        let mut i = 0usize;
        while i < num_symbols {
            let off = sym_table_off + i * SYMBOL_SIZE;
            if off + SYMBOL_SIZE > bytes.len() {
                return Err(CoffError::Truncated);
            }
            let rec = &bytes[off..off + SYMBOL_SIZE];
            let name = if rec[0] == 0 && rec[1] == 0 && rec[2] == 0 && rec[3] == 0 {
                let off_in_st = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                if strtab.get(off_in_st).is_none() {
                    return Err(CoffError::BadStringOffset(off_in_st));
                }
                SymName::Long(off_in_st)
            } else {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&rec[0..8]);
                SymName::Short(arr)
            };
            let value = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
            let section_raw = i16::from_le_bytes([rec[12], rec[13]]);
            let type_raw = u16::from_le_bytes([rec[14], rec[15]]);
            let storage =
                StorageClass::from_u8(rec[16]).ok_or(CoffError::BadStorageClass(rec[16]))?;
            let n_aux = rec[17] as usize;

            // Map disk-index `i` to user-index `symbols.len()`.
            for _ in 0..=n_aux {
                disk_to_user.push(symbols.len() as u32);
            }

            let mut aux_vec: Vec<AuxRecord> = Vec::with_capacity(n_aux);
            for a in 0..n_aux {
                let ao = sym_table_off + (i + 1 + a) * SYMBOL_SIZE;
                if ao + SYMBOL_SIZE > bytes.len() {
                    return Err(CoffError::Truncated);
                }
                let arec = &bytes[ao..ao + SYMBOL_SIZE];
                // We decode every aux as a Section-Def if the parent is
                // STATIC (a section symbol), Weak-Extern if the parent
                // is WEAK_EXTERNAL, and otherwise pass through as raw
                // SectionDef-shaped bytes (the safer of the two).
                let decoded = if storage == StorageClass::Static {
                    let length = u32::from_le_bytes([arec[0], arec[1], arec[2], arec[3]]);
                    let num_relocs = u16::from_le_bytes([arec[4], arec[5]]);
                    let checksum = u32::from_le_bytes([arec[8], arec[9], arec[10], arec[11]]);
                    let number = u16::from_le_bytes([arec[12], arec[13]]);
                    let sel_raw = arec[14];
                    let selection = if sel_raw == 0 {
                        None
                    } else {
                        Some(
                            ComdatSelect::from_u8(sel_raw)
                                .ok_or(CoffError::BadComdatSelection(sel_raw))?,
                        )
                    };
                    AuxRecord::SectionDef {
                        length,
                        num_relocs,
                        checksum,
                        number,
                        selection,
                    }
                } else if storage == StorageClass::WeakExternal {
                    let tag = u32::from_le_bytes([arec[0], arec[1], arec[2], arec[3]]);
                    let characteristics = u32::from_le_bytes([arec[4], arec[5], arec[6], arec[7]]);
                    AuxRecord::WeakExtern {
                        tag,
                        characteristics,
                    }
                } else {
                    // Aux records on EXTERNAL function symbols (Format 4
                    // FunctionDef) are not in mdbcc's IR today. Decode
                    // as a benign SectionDef so round-trip preserves
                    // shape without bespoke variants.
                    let length = u32::from_le_bytes([arec[0], arec[1], arec[2], arec[3]]);
                    let num_relocs = u16::from_le_bytes([arec[4], arec[5]]);
                    let checksum = u32::from_le_bytes([arec[8], arec[9], arec[10], arec[11]]);
                    let number = u16::from_le_bytes([arec[12], arec[13]]);
                    let sel_raw = arec[14];
                    let selection = if sel_raw == 0 {
                        None
                    } else {
                        ComdatSelect::from_u8(sel_raw)
                    };
                    AuxRecord::SectionDef {
                        length,
                        num_relocs,
                        checksum,
                        number,
                        selection,
                    }
                };
                aux_vec.push(decoded);
            }

            symbols.push(Symbol {
                name,
                value,
                section: SectionRef::from_i16(section_raw),
                kind: SymKind::from_type(type_raw),
                storage,
                aux: aux_vec,
            });

            i += 1 + n_aux;
        }
        if i != num_symbols {
            return Err(CoffError::BadAuxCount);
        }

        // Remap relocation symbol indices from disk → user.
        for sec in sections.iter_mut() {
            for r in sec.relocs.iter_mut() {
                if (r.symbol as usize) < disk_to_user.len() {
                    r.symbol = disk_to_user[r.symbol as usize];
                }
            }
        }

        // Reconstruct COMDAT descriptors. The convention used by the
        // encoder is: a section is COMDAT iff its IMAGE_SCN_LNK_COMDAT
        // characteristic bit is set; the leader STATIC section symbol
        // (the symbol whose `section` points at this section and whose
        // storage is STATIC) carries the aux SectionDef with the
        // selection code in the first such record.
        for (sec_ix0, sec) in sections.iter_mut().enumerate() {
            if sec.characteristics & IMAGE_SCN_LNK_COMDAT == 0 {
                continue;
            }
            let sec_ix1 = (sec_ix0 + 1) as i16;
            let mut comdat = None;
            for sym in &symbols {
                if sym.storage != StorageClass::Static {
                    continue;
                }
                if sym.section != SectionRef::Section(sec_ix1 as u16) {
                    continue;
                }
                if let Some(AuxRecord::SectionDef {
                    selection: Some(sel),
                    number,
                    ..
                }) = sym.aux.first()
                {
                    comdat = Some(Comdat {
                        selection: *sel,
                        associated_section: *number,
                    });
                    break;
                }
            }
            sec.comdat = comdat;
        }

        // Lift any synthesised .drectve section back into `directives`.
        // The encoder will re-synthesise it on the next write — having
        // the IR carry both `directives` and a `.drectve` section is
        // redundant. We DO retain the section if it carries non-default
        // characteristics (the round-trip is structural; clients that
        // care can compare the two `.drectve` representations).
        let mut directives: Vec<u8> = Vec::new();
        for sec in &sections {
            if matches!(sec.name, SectionName::Drectve)
                && sec.characteristics == (IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE)
            {
                directives = sec.data.clone();
                break;
            }
        }
        // Drop a single synthesised .drectve to keep round-trip equality
        // when `directives` was set on the source IR.
        if !directives.is_empty()
            && let Some(pos) = sections.iter().position(|s| {
                matches!(s.name, SectionName::Drectve)
                    && s.characteristics == (IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE)
                    && s.data == directives
            })
        {
            sections.remove(pos);
        }

        let symbol_source_locs = vec![None; symbols.len()];
        Ok(Object {
            machine,
            sections,
            symbols,
            strtab,
            directives,
            symbol_source_locs,
        })
    }
}

/// Decode the 8-byte section-name slot to its rendered string form.
/// Handles both the inline form (up to 8 ASCII bytes, NUL-terminated
/// or padded) and the long form (`/<decimal_offset>` into strtab).
fn decode_section_name_slot(slot: &[u8; 8], st: &StringTable) -> Result<String, CoffError> {
    if slot[0] == b'/' {
        // Long form. Strip the leading '/', parse the decimal offset,
        // and look it up in strtab.
        let end = slot.iter().position(|&b| b == 0).unwrap_or(8);
        let digits = &slot[1..end];
        let s = std::str::from_utf8(digits).map_err(|_| CoffError::BadSectionName)?;
        let off: u32 = s.parse().map_err(|_| CoffError::BadSectionName)?;
        let bytes = st.get(off).ok_or(CoffError::BadStringOffset(off))?;
        let s = std::str::from_utf8(bytes).map_err(|_| CoffError::BadSectionName)?;
        Ok(s.to_string())
    } else {
        let end = slot.iter().position(|&b| b == 0).unwrap_or(8);
        let s = std::str::from_utf8(&slot[..end]).map_err(|_| CoffError::BadSectionName)?;
        Ok(s.to_string())
    }
}

/// Recognise a rendered section name as one of our canonical
/// `SectionName` variants. Unknown names land in `Custom` so the round-
/// trip preserves the literal.
fn parse_section_name(s: &str) -> Result<SectionName, CoffError> {
    Ok(match s {
        ".text" => SectionName::Text,
        ".data" => SectionName::Data,
        ".bss" => SectionName::Bss,
        ".rdata" => SectionName::Rdata,
        ".pdata" => SectionName::Pdata,
        ".xdata" => SectionName::Xdata,
        ".drectve" => SectionName::Drectve,
        other => {
            if let Some(rest) = other.strip_prefix(".text$") {
                SectionName::TextComdat(rest.to_string())
            } else if let Some(rest) = other.strip_prefix(".rdata$") {
                // ".rdata$xt$<class>" is a Custom for the moment; we
                // don't have a dedicated variant for it. Leave as
                // Custom so round-trips preserve the literal. (S1b.4
                // may pick a richer variant when typeinfo emission
                // wires up.)
                if rest.starts_with("xt$") {
                    SectionName::Custom(other.to_string())
                } else {
                    SectionName::RdataComdat(rest.to_string())
                }
            } else if let Some(rest) = other.strip_prefix(".xdata$") {
                SectionName::XdataComdat(rest.to_string())
            } else if let Some(rest) = other.strip_prefix(".pdata$") {
                SectionName::PdataComdat(rest.to_string())
            } else {
                SectionName::Custom(other.to_string())
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Unit tests for the pure pieces (strtab, encoding helpers).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtab_dedup_returns_same_offset() {
        let mut st = StringTable::new();
        let a = st.intern("hello");
        let b = st.intern("world");
        let c = st.intern("hello");
        assert_eq!(a, c, "intern dedup");
        assert_ne!(a, b);
        // body layout: "hello\0world\0"
        assert_eq!(st.bytes, b"hello\0world\0");
        assert_eq!(a, 4);
        assert_eq!(b, 10);
    }

    #[test]
    fn strtab_finalize_writes_size_prefix() {
        let mut st = StringTable::new();
        st.intern("abc");
        let bytes = st.finalize();
        // size = 4 (prefix) + 4 (abc\0) = 8
        assert_eq!(&bytes[..4], &8u32.to_le_bytes());
        assert_eq!(&bytes[4..], b"abc\0");
    }

    #[test]
    fn strtab_empty_finalize_is_four_bytes() {
        let st = StringTable::new();
        assert_eq!(st.finalize(), 4u32.to_le_bytes().to_vec());
    }

    #[test]
    fn section_name_short_fits_inline() {
        let mut st = StringTable::new();
        let slot = SectionName::Text.encode_to_strtab(&mut st);
        assert_eq!(&slot, b".text\0\0\0");
        assert!(st.bytes.is_empty());
    }

    #[test]
    fn section_name_long_uses_slash_decimal() {
        let mut st = StringTable::new();
        let slot =
            SectionName::Custom(".rdata$xt$VeryLongClass".to_string()).encode_to_strtab(&mut st);
        assert_eq!(slot[0], b'/');
        // Decoded offset must match what intern returned.
        let off = std::str::from_utf8(&slot[1..])
            .unwrap()
            .trim_end_matches('\0')
            .parse::<u32>()
            .unwrap();
        assert_eq!(off, 4);
        assert_eq!(st.get_str(off), Some(".rdata$xt$VeryLongClass"));
    }

    #[test]
    fn long_name_slot_layout() {
        // 4 zero bytes followed by LE offset.
        assert_eq!(long_name_slot(0x42), [0, 0, 0, 0, 0x42, 0, 0, 0]);
    }
}
