//! S1c.8 — synthesised CRT startup stub.
//!
//! When `LinkOpts::synthesise_crt == true`, [`crate::link::link`] prepends a
//! synthetic [`coff::Object`] (built here by [`synthesise_startup_object`]) to
//! the input list. The object provides:
//!
//! 1. `mainCRTStartup` (Console) or `WinMainCRTStartup` (GUI) — the entry
//!    function the PE header points at. It calls `__do_global_ctors`, then
//!    the user's `main`/`WinMain`, then `ExitProcess`.
//! 2. `__do_global_ctors` — walks the merged `.CRT$XC*` array invoking each
//!    non-NULL function pointer. The array is bounded by `__xc_a` (start)
//!    and `__xc_z` (end).
//! 3. `.CRT$XCL` (8 bytes of zeros, begin sentinel) and `.CRT$XCZ` (8 bytes
//!    of zeros, end sentinel). When user objects contribute `.CRT$XCU.*`
//!    sections (one 8-byte ctor pointer each), the linker merges all
//!    `.CRT$*` sections lexicographically into `.rdata`, producing a
//!    contiguous array between the two sentinels. The walker iterates
//!    `[__xc_a, __xc_z)`; the leading NULL in `.CRT$XCL` is skipped via the
//!    `test rax, rax; jz` check inside the loop, and the trailing NULL in
//!    `.CRT$XCZ` is never reached because `rbx < r12` terminates first.
//!
//! ## Why a synthesised Object (Q-CRT ratification — HLD §10)
//!
//! Per HLD §5.3 the real Borland CRT (`STARTUP.C` / `C0NT.ASM`) lives on the
//! BC45 CD and gets linked from `crt.lib` once S5 builds it. Until then
//! mdlink bakes its own minimum. The stub's symbols use
//! [`StorageClass::WeakExternal`] so S5+ a real CRT definition WOULD win
//! (when the linker's weak-overrides-strong path matures — currently
//! [`crate::link::pe_writer::resolved_symbol_rva_multi`] accepts WeakExternal
//! and a single weak definition resolves cleanly; the
//! prefer-strong-over-weak ordering is filed as a follow-up for S5).
//!
//! ## Argv marshalling (deferred to S8)
//!
//! Per the scope-limiting clause in the S1c.8 brief, this stub passes
//! `argc=0, argv=NULL, envp=NULL` (or `hPrevInstance=NULL,
//! lpCmdLine=NULL` for GUI). Real argv parsing via `GetCommandLineA` +
//! tokeniser is S8 work. Programs that don't read argv (the 88 e2e set,
//! every C++ test in the project) are unaffected; programs that DO read
//! argv would see empty input — file as a known limitation if needed.
//!
//! ## Stub co-evolution constraint (HLD §5.1)
//!
//! The stub does NOT participate in `.pdata`/`.xdata` SEH unwind metadata
//! (it has no try/catch and never raises an exception that needs to unwind
//! through it; the `int3` after `call ExitProcess` is unreachable). When
//! mdbcc's standard prologue shape changes (currently `push rbp; mov
//! rbp,rsp; sub rsp,imm32` per `tests/two_file_link.rs`), the stub's stack
//! discipline (`sub rsp, 0x28`) does NOT need to change — the stub never
//! has a SEH personality routine attached. If S8 adds argv parsing or
//! atexit registration, that's the moment to add an `.xdata` entry.

use crate::coff::{
    self, AuxRecord, Object, Reloc, RelocKind, Section, SectionName, SectionRef, StorageClass,
    SymKind, SymName, Symbol,
};
use crate::link::{LinkOpts, Subsystem};

/// The legacy writer's fixed image base. Baked into the GUI stub so we
/// avoid a `GetModuleHandleA` import (the EXE's module handle equals its
/// image base; see `pe_writer::write_entry_stub` GUI branch for the same
/// trick).
const IMAGE_BASE: u64 = 0x1_4000_0000;

/// Build the synthesised CRT startup object. Per the S1c.8 brief, this is a
/// single [`Object`] containing the entry stub, the ctor walker, the
/// `.CRT$XC*` sentinels, and references to user `main` / `WinMain` plus
/// `__imp_ExitProcess`.
///
/// # Section layout
///
/// - **Section 1** — `.text` (CODE | EXECUTE | READ): `mainCRTStartup` (or
///   `WinMainCRTStartup`) immediately followed by `__do_global_ctors`. Both
///   functions are emitted by [`build_text_bytes`].
/// - **Section 2** — `.CRT$XCL` (RDATA | READ): 8 zero bytes (begin
///   sentinel). `__xc_a` lives at offset 0.
/// - **Section 3** — `.CRT$XCZ` (RDATA | READ): 8 zero bytes (end
///   sentinel). `__xc_z` lives at offset 0.
///
/// `.text` carries `text_bytes.len()` bytes and `relocs.len()` relocations
/// to be patched by [`crate::link::pe_writer::apply_relocs_multi`].
///
/// # Symbol table
///
/// | Index | Name                | Storage      | Section              | Notes |
/// |-------|---------------------|--------------|----------------------|-------|
/// | 0     | `.text`             | Static       | Section(1)           | Aux SectionDef |
/// | 1     | `mainCRTStartup` (or `WinMainCRTStartup`) | WeakExternal | Section(1) at offset 0 | Entry-point candidate |
/// | 2     | `__do_global_ctors` | WeakExternal | Section(1) at stub end |               |
/// | 3     | `.CRT$XCL`          | Static       | Section(2)           | Aux SectionDef |
/// | 4     | `__xc_a`            | Static       | Section(2) at offset 0 | Begin sentinel |
/// | 5     | `.CRT$XCZ`          | Static       | Section(3)           | Aux SectionDef |
/// | 6     | `__xc_z`            | Static       | Section(3) at offset 0 | End sentinel |
/// | 7     | `main` (or `WinMain`) | External   | Undefined            | Resolved cross-object |
/// | 8     | `__imp_ExitProcess` | External     | Undefined            | Resolved via IAT |
pub fn synthesise_startup_object(opts: &LinkOpts) -> Object {
    let entry_name = match opts.subsystem {
        Subsystem::Console => "mainCRTStartup",
        Subsystem::Gui => "WinMainCRTStartup",
    };
    let user_entry_name = match opts.subsystem {
        Subsystem::Console => "main",
        Subsystem::Gui => "WinMain",
    };

    // Build the .text byte image. We do this in a structured way (one helper
    // per instruction) so the byte sequence is auditable and the relocation
    // offsets are derived, not hard-coded against magic numbers.
    let (text_bytes, relocs_plan) = build_text_bytes(opts.subsystem);

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };

    // ---- Symbol table layout (indices match the doc-comment table) -------
    // We allocate symbol indices BEFORE pushing sections so the section
    // relocations can reference them by index. The convention used by the
    // existing two_file_link/archive_link fixtures: section symbol immediately
    // followed by the symbols it defines, then external references.

    // [0] .text section symbol — Static, aux SectionDef. The encoder requires
    //     SectionDef aux for every section symbol (see coff::Object::write).
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: text_bytes.len() as u32,
            num_relocs: relocs_plan.len() as u16,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // [1] entry symbol — WeakExternal so a real CRT (S5+) can override.
    obj.symbols.push(Symbol {
        name: SymName::from_str(entry_name, &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::WeakExternal,
        aux: Vec::new(),
    });
    // [2] __do_global_ctors — WeakExternal too.
    let ctors_offset = stub_size(opts.subsystem) as u32;
    obj.symbols.push(Symbol {
        name: SymName::from_str("__do_global_ctors", &mut obj.strtab),
        value: ctors_offset,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::WeakExternal,
        aux: Vec::new(),
    });
    // [3] .CRT$XCL section symbol.
    obj.symbols.push(Symbol {
        name: SymName::from_str(".CRT$XCL", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(2),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 8,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // [4] __xc_a — begin sentinel (Static, at offset 0 of .CRT$XCL).
    obj.symbols.push(Symbol {
        name: SymName::from_str("__xc_a", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(2),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: Vec::new(),
    });
    // [5] .CRT$XCZ section symbol.
    obj.symbols.push(Symbol {
        name: SymName::from_str(".CRT$XCZ", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(3),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 8,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // [6] __xc_z — end sentinel (Static, at offset 0 of .CRT$XCZ).
    obj.symbols.push(Symbol {
        name: SymName::from_str("__xc_z", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(3),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: Vec::new(),
    });
    // [7] main / WinMain — External undefined; resolved cross-object.
    obj.symbols.push(Symbol {
        name: SymName::from_str(user_entry_name, &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    // [8] __imp_ExitProcess — External undefined; resolved via IAT.
    obj.symbols.push(Symbol {
        name: SymName::from_str("__imp_ExitProcess", &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Notype,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    // Symbol indices for the reloc plan (must match the table above).
    const SYM_DO_GLOBAL_CTORS: u32 = 2;
    const SYM_XC_A: u32 = 4;
    const SYM_XC_Z: u32 = 6;
    const SYM_USER_ENTRY: u32 = 7;
    const SYM_IMP_EXITPROCESS: u32 = 8;

    // Translate the symbolic reloc plan into real Relocs against the
    // symbol indices above.
    let relocs: Vec<Reloc> = relocs_plan
        .iter()
        .map(|rp| Reloc {
            offset: rp.offset,
            symbol: match rp.target {
                RelocTarget::DoGlobalCtors => SYM_DO_GLOBAL_CTORS,
                RelocTarget::XcA => SYM_XC_A,
                RelocTarget::XcZ => SYM_XC_Z,
                RelocTarget::UserEntry => SYM_USER_ENTRY,
                RelocTarget::ImpExitProcess => SYM_IMP_EXITPROCESS,
            },
            kind: rp.kind,
        })
        .collect();

    // ---- Section table ---------------------------------------------------
    // Section 1: .text
    obj.sections.push(Section {
        data: text_bytes,
        relocs,
        ..Section::text()
    });
    // Section 2: .CRT$XCL — 8 zero bytes (begin sentinel). Routed to .rdata
    // by the linker's merge pass; characteristics mark it as initialised
    // read-only data with 8-byte alignment (matches `.rdata`'s default).
    obj.sections.push(Section {
        name: SectionName::Custom(".CRT$XCL".to_string()),
        data: vec![0u8; 8],
        bss_size: 0,
        relocs: Vec::new(),
        // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_8BYTES
        characteristics: 0x4040_0040,
        comdat: None,
    });
    // Section 3: .CRT$XCZ — 8 zero bytes (end sentinel).
    obj.sections.push(Section {
        name: SectionName::Custom(".CRT$XCZ".to_string()),
        data: vec![0u8; 8],
        bss_size: 0,
        relocs: Vec::new(),
        characteristics: 0x4040_0040,
        comdat: None,
    });

    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// Reloc target (symbolic) used by the planning pass in
/// [`build_text_bytes`]. Translated to a concrete symbol index by the
/// caller [`synthesise_startup_object`].
#[derive(Debug, Clone, Copy)]
enum RelocTarget {
    DoGlobalCtors,
    XcA,
    XcZ,
    UserEntry,
    ImpExitProcess,
}

/// A planned relocation: file-offset within `.text` of the 4-byte slot,
/// the target (resolved to a symbol index later), and the kind.
#[derive(Debug, Clone, Copy)]
struct RelocPlan {
    offset: u32,
    target: RelocTarget,
    kind: RelocKind,
}

/// Build the `.text` byte image and the parallel reloc plan for the chosen
/// subsystem. Returns `(bytes, relocs)`.
///
/// The byte image is `mainCRTStartup` (or `WinMainCRTStartup`) immediately
/// followed by `__do_global_ctors`. Both functions live in the same section
/// so the call between them resolves intra-section (a REL32 with both site
/// and target inside the synth Object's `.text`).
fn build_text_bytes(subsystem: Subsystem) -> (Vec<u8>, Vec<RelocPlan>) {
    let mut bytes: Vec<u8> = Vec::with_capacity(128);
    let mut relocs: Vec<RelocPlan> = Vec::new();

    // ---- Entry stub ------------------------------------------------------
    match subsystem {
        Subsystem::Console => emit_console_stub(&mut bytes, &mut relocs),
        Subsystem::Gui => emit_gui_stub(&mut bytes, &mut relocs),
    }
    debug_assert_eq!(bytes.len(), stub_size(subsystem));

    // ---- __do_global_ctors ----------------------------------------------
    emit_do_global_ctors(&mut bytes, &mut relocs);

    (bytes, relocs)
}

/// Size of the entry stub in bytes (so [`synthesise_startup_object`] can
/// compute `__do_global_ctors`'s offset within `.text` without emitting the
/// bytes twice). MUST match the byte count emitted by [`emit_console_stub`]
/// / [`emit_gui_stub`] respectively; debug-asserted at build time.
fn stub_size(subsystem: Subsystem) -> usize {
    match subsystem {
        Subsystem::Console => 0x1E, // 30 bytes
        Subsystem::Gui => 0x2C,     // 44 bytes
    }
}

/// Emit the Console `mainCRTStartup` byte sequence:
/// ```text
///   00: 48 83 EC 28          sub rsp, 0x28          ; Win64 ABI shadow + 16-align
///   04: E8 <rel32>           call __do_global_ctors  ; REL32 at offset 0x05
///   09: 31 C9                xor ecx, ecx            ; argc = 0
///   0B: 31 D2                xor edx, edx            ; argv = NULL
///   0D: 45 31 C0             xor r8d, r8d            ; envp = NULL (zero-extends r8)
///   10: E8 <rel32>            call main              ; REL32 at offset 0x11
///   15: 89 C1                mov ecx, eax            ; exit code → arg0
///   17: FF 15 <disp32>       call qword ptr [rip+disp] ; ExitProcess via IAT
///   1D: CC                   int3                    ; unreachable
/// ```
fn emit_console_stub(bytes: &mut Vec<u8>, relocs: &mut Vec<RelocPlan>) {
    let base = bytes.len();
    debug_assert_eq!(base, 0, "console stub must be at offset 0 of .text");

    // sub rsp, 0x28
    bytes.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    // call __do_global_ctors (E8 + REL32). The reloc patches the 4-byte
    // displacement after the 0xE8 opcode.
    bytes.push(0xE8);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::DoGlobalCtors,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // xor ecx, ecx
    bytes.extend_from_slice(&[0x31, 0xC9]);
    // xor edx, edx
    bytes.extend_from_slice(&[0x31, 0xD2]);
    // xor r8d, r8d (REX.R=1 to address r8d; 32-bit operation zero-extends
    // to 64 bits, matching Win64 ABI "envp = NULL" cleanly).
    bytes.extend_from_slice(&[0x45, 0x31, 0xC0]);
    // call main
    bytes.push(0xE8);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::UserEntry,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // mov ecx, eax (the user's int return → first arg of ExitProcess)
    bytes.extend_from_slice(&[0x89, 0xC1]);
    // call qword ptr [rip+disp32] — indirect via IAT slot.
    // 0xFF /2 with ModR/M=00_010_101 (mod=00, reg=010 i.e. /2, r/m=101 i.e.
    // RIP-relative disp32). The REL32 reloc on __imp_ExitProcess resolves
    // to the IAT slot's RVA; apply_one_reloc's Rel32 path computes
    // `slot_rva - (site_rva + 4)`, which is exactly the disp the CPU adds
    // to RIP to reach the slot.
    bytes.extend_from_slice(&[0xFF, 0x15]);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::ImpExitProcess,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // int3 — unreachable (ExitProcess never returns)
    bytes.push(0xCC);

    debug_assert_eq!(
        bytes.len() - base,
        0x1E,
        "console stub size mismatch (update stub_size)"
    );
}

/// Emit the GUI `WinMainCRTStartup` byte sequence. Same shape as the
/// console stub but marshals the four `WinMain` arguments: `hInstance =
/// IMAGE_BASE` (baked imm64 — see the matching trick in
/// `pe_writer::write_entry_stub`'s GUI branch), `hPrevInstance = NULL`,
/// `lpCmdLine = NULL`, `nCmdShow = SW_SHOWNORMAL = 1`.
fn emit_gui_stub(bytes: &mut Vec<u8>, relocs: &mut Vec<RelocPlan>) {
    let base = bytes.len();
    debug_assert_eq!(base, 0, "GUI stub must be at offset 0 of .text");

    // sub rsp, 0x28
    bytes.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    // call __do_global_ctors
    bytes.push(0xE8);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::DoGlobalCtors,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // mov rcx, IMAGE_BASE (48 B9 imm64)
    bytes.extend_from_slice(&[0x48, 0xB9]);
    bytes.extend_from_slice(&IMAGE_BASE.to_le_bytes());
    // xor edx, edx (hPrevInstance = NULL)
    bytes.extend_from_slice(&[0x31, 0xD2]);
    // xor r8d, r8d (lpCmdLine = NULL)
    bytes.extend_from_slice(&[0x45, 0x31, 0xC0]);
    // mov r9d, 1 (nCmdShow = SW_SHOWNORMAL)
    bytes.extend_from_slice(&[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00]);
    // call WinMain
    bytes.push(0xE8);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::UserEntry,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // mov ecx, eax
    bytes.extend_from_slice(&[0x89, 0xC1]);
    // call qword ptr [rip+disp32] — ExitProcess via IAT slot.
    bytes.extend_from_slice(&[0xFF, 0x15]);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::ImpExitProcess,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // int3 — unreachable
    bytes.push(0xCC);

    debug_assert_eq!(
        bytes.len() - base,
        0x2C,
        "GUI stub size mismatch (update stub_size)"
    );
}

/// Emit `__do_global_ctors`. Walks the merged `.CRT$XC*` array from
/// `__xc_a` (inclusive) to `__xc_z` (exclusive), calling each non-NULL
/// `void(*)(void)` pointer it sees.
///
/// ```text
///   00: 53                   push rbx                ; preserve nonvol; RSP→8 mod 16
///   01: 41 54                push r12                ; preserve nonvol; RSP→0 mod 16
///   03: 48 83 EC 28          sub rsp, 0x28           ; shadow space; RSP→8 mod 16
///   07: 48 8D 1D <rel32>     lea rbx, [rip+__xc_a]   ; REL32 at offset 0x0A
///   0E: 4C 8D 25 <rel32>     lea r12, [rip+__xc_z]   ; REL32 at offset 0x11
///   15: 4C 39 E3             cmp rbx, r12            ; LOOP:
///   18: 73 10                jae .done
///   1A: 48 8B 03             mov rax, [rbx]
///   1D: 48 85 C0             test rax, rax
///   20: 74 02                jz .skip
///   22: FF D0                call rax
///   24: 48 83 C3 08          add rbx, 8              ; .skip:
///   28: EB EB                jmp .loop               ; rel8 = -21
///   2A: 48 83 C4 28          add rsp, 0x28           ; .done:
///   2E: 41 5C                pop r12
///   30: 5B                   pop rbx
///   31: C3                   ret
/// ```
///
/// Note on stack alignment: at function entry (after the caller's `call`)
/// RSP ≡ 8 (mod 16). After `push rbx` RSP ≡ 0; after `push r12` RSP ≡ 8;
/// after `sub rsp, 0x28` RSP ≡ 0. So `call rax` enters its callee with
/// RSP ≡ 8 (mod 16) — correct per Win64 ABI.
fn emit_do_global_ctors(bytes: &mut Vec<u8>, relocs: &mut Vec<RelocPlan>) {
    let base = bytes.len();
    // push rbx
    bytes.push(0x53);
    // push r12 (REX.B=1 to address r12)
    bytes.extend_from_slice(&[0x41, 0x54]);
    // sub rsp, 0x28
    bytes.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    // lea rbx, [rip+__xc_a] (48 8D 1D + REL32). REL32 reloc on __xc_a.
    bytes.extend_from_slice(&[0x48, 0x8D, 0x1D]);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::XcA,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // lea r12, [rip+__xc_z] (4C 8D 25 + REL32).
    bytes.extend_from_slice(&[0x4C, 0x8D, 0x25]);
    relocs.push(RelocPlan {
        offset: bytes.len() as u32,
        target: RelocTarget::XcZ,
        kind: RelocKind::Rel32,
    });
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // cmp rbx, r12 (4C 39 E3) — REX.W=1, REX.R=1; reg=r12 (low 3 = 100);
    // r/m=rbx (low 3 = 011); ModR/M = 11_100_011 = 0xE3.
    let loop_start_off = bytes.len() as i32;
    bytes.extend_from_slice(&[0x4C, 0x39, 0xE3]);
    // jae .done — placeholder, patched after we know `.done` offset.
    bytes.extend_from_slice(&[0x73, 0x00]);
    let jae_disp_off = bytes.len() - 1; // offset of the rel8 byte
    let jae_next_ip = bytes.len() as i32;
    // mov rax, [rbx] (48 8B 03 — REX.W=1, opcode 8B /r, ModR/M=00_000_011 = 0x03)
    bytes.extend_from_slice(&[0x48, 0x8B, 0x03]);
    // test rax, rax (48 85 C0)
    bytes.extend_from_slice(&[0x48, 0x85, 0xC0]);
    // jz .skip — placeholder, patched.
    bytes.extend_from_slice(&[0x74, 0x00]);
    let jz_disp_off = bytes.len() - 1;
    let jz_next_ip = bytes.len() as i32;
    // call rax (FF D0)
    bytes.extend_from_slice(&[0xFF, 0xD0]);
    // .skip:
    let skip_off = bytes.len() as i32;
    // add rbx, 8 (48 83 C3 08)
    bytes.extend_from_slice(&[0x48, 0x83, 0xC3, 0x08]);
    // jmp .loop (EB rel8)
    bytes.extend_from_slice(&[0xEB, 0x00]);
    let jmp_disp_off = bytes.len() - 1;
    let jmp_next_ip = bytes.len() as i32;
    // .done:
    let done_off = bytes.len() as i32;
    // add rsp, 0x28
    bytes.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // pop r12 (REX.B=1 → 41 5C)
    bytes.extend_from_slice(&[0x41, 0x5C]);
    // pop rbx
    bytes.push(0x5B);
    // ret
    bytes.push(0xC3);

    // Patch the three short-jump displacements.
    let jae_disp = done_off - jae_next_ip;
    let jz_disp = skip_off - jz_next_ip;
    let jmp_disp = loop_start_off - jmp_next_ip;
    debug_assert!((-128..=127).contains(&jae_disp), "jae out of rel8 range");
    debug_assert!((-128..=127).contains(&jz_disp), "jz out of rel8 range");
    debug_assert!((-128..=127).contains(&jmp_disp), "jmp out of rel8 range");
    bytes[jae_disp_off] = jae_disp as i8 as u8;
    bytes[jz_disp_off] = jz_disp as i8 as u8;
    bytes[jmp_disp_off] = jmp_disp as i8 as u8;

    debug_assert_eq!(
        bytes.len() - base,
        0x32,
        "__do_global_ctors size drifted; update doc-comment table"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_stub_size_matches_table() {
        let mut b = Vec::new();
        let mut r = Vec::new();
        emit_console_stub(&mut b, &mut r);
        assert_eq!(b.len(), 0x1E);
        // Three relocs: do_global_ctors, main, __imp_ExitProcess
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn gui_stub_size_matches_table() {
        let mut b = Vec::new();
        let mut r = Vec::new();
        emit_gui_stub(&mut b, &mut r);
        assert_eq!(b.len(), 0x2C);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn do_global_ctors_size_matches_table() {
        let mut b = Vec::new();
        let mut r = Vec::new();
        emit_do_global_ctors(&mut b, &mut r);
        assert_eq!(b.len(), 0x32);
        // Two relocs: __xc_a, __xc_z
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn synthesise_console_object_shape() {
        let opts = LinkOpts {
            subsystem: Subsystem::Console,
            ..LinkOpts::default()
        };
        let obj = synthesise_startup_object(&opts);
        assert_eq!(obj.sections.len(), 3, ".text + .CRT$XCL + .CRT$XCZ");
        // .text contains stub (0x1E) + __do_global_ctors (0x32) = 0x50.
        assert_eq!(obj.sections[0].data.len(), 0x50);
        // .CRT$XCL and .CRT$XCZ each contribute 8 bytes of zeros.
        assert_eq!(obj.sections[1].data, vec![0u8; 8]);
        assert_eq!(obj.sections[2].data, vec![0u8; 8]);
        // Five relocs in .text: 3 from console stub + 2 from ctor walker.
        assert_eq!(obj.sections[0].relocs.len(), 5);
        // Symbol count: 9 (per the doc-comment table).
        assert_eq!(obj.symbols.len(), 9);
        // symbol_source_locs has the same length (parallel array).
        assert_eq!(obj.symbol_source_locs.len(), 9);
    }

    #[test]
    fn synthesise_gui_object_uses_winmaincrtstartup() {
        let opts = LinkOpts {
            subsystem: Subsystem::Gui,
            ..LinkOpts::default()
        };
        let obj = synthesise_startup_object(&opts);
        // .text is GUI stub (0x2C) + __do_global_ctors (0x32) = 0x5E.
        assert_eq!(obj.sections[0].data.len(), 0x5E);
        // Verify entry name (symbol [1]): WinMainCRTStartup.
        let entry = &obj.symbols[1];
        let n = match &entry.name {
            SymName::Short(_) => unreachable!("WinMainCRTStartup is 17 chars > 8"),
            SymName::Long(off) => obj.strtab.get_str(*off).unwrap().to_string(),
        };
        assert_eq!(n, "WinMainCRTStartup");
    }

    #[test]
    fn synth_object_roundtrips_through_coff_encoder() {
        // The synthesised object MUST survive Object::write → Object::read
        // round-trip; otherwise the linker can't consume CoffBytes inputs
        // emitting an equivalent on-disk synth. Smoke-test both subsystems.
        for subsystem in [Subsystem::Console, Subsystem::Gui] {
            let opts = LinkOpts {
                subsystem,
                ..LinkOpts::default()
            };
            let obj = synthesise_startup_object(&opts);
            let bytes = obj.write();
            let parsed = Object::read(&bytes).expect("round-trip");
            assert_eq!(obj.sections.len(), parsed.sections.len());
            assert_eq!(obj.symbols.len(), parsed.symbols.len());
        }
    }
}
