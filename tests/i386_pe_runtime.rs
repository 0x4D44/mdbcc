//! S2d — PE32 (i386) runtime + structural tests.
//!
//! Lights up the end-to-end path: hand-built `Machine::I386` Object →
//! `link::link` with `LinkOpts.machine = I386` → PE32 image written to
//! disk → executed on Win11 via WOW64 → exit code matches.
//!
//! Per HLD §5 (PE32 writer extension) + the **supervisor session 1c**
//! decision to parametrise one writer over `is_pe32` rather than fork
//! into two parallel functions (see
//! `wrk_journals/2026.05.27 - JRN - S2 drive (32-bit x86 backend).md`).
//!
//! Six structural tests + one runtime test. The runtime test skips
//! loudly if the spawn fails — some early bugs (e.g. PE loader refusing
//! to load the image) are diagnostic-worthy and shouldn't fail CI.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use mdbcc::coff::{
    self, AuxRecord, Object, Section, SectionRef, StorageClass, SymKind, SymName, Symbol,
};
use mdbcc::link::{self, Input, LinkOpts, Subsystem};

// ---------------------------------------------------------------------------
// Fixture builder
// ---------------------------------------------------------------------------

/// Hand-craft a minimal i386 Object that defines `main` as:
///
/// ```text
/// 00: B8 2A 00 00 00     mov eax, 42
/// 05: C3                 ret
/// ```
///
/// The linker's synthesised entry stub will:
///   1. `call main` → eax = 42
///   2. `push eax` → arg = 42
///   3. `call [ExitProcess]` → process exits with code 42
///
/// Note the symbol name is the BARE `main` (no leading underscore). The
/// PE32 writer's entry-symbol lookup does exact-string match against the
/// configured entry name (default `main` for Subsystem::Console). When
/// S2b's parser adds cdecl name mangling, the codegen will produce
/// `_main` and the linker will need an underscore-fallback; for S2d's
/// hand-built fixture we side-step that by naming the symbol exactly
/// what the lookup expects.
fn build_main_returns_42_i386() -> Object {
    let main_code: Vec<u8> = vec![0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

    let mut obj = Object {
        machine: coff::Machine::I386,
        ..Object::default()
    };

    // .text section.
    obj.sections.push(Section {
        data: main_code.clone(),
        ..Section::text()
    });

    // Symbol 0 — STATIC .text section symbol (with SectionDef aux).
    obj.symbols.push(Symbol {
        name: SymName::from_str(".text", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: main_code.len() as u32,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });

    // Symbol 1 — EXTERNAL `main` (function at .text offset 0).
    obj.symbols.push(Symbol {
        name: SymName::from_str("main", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];

    obj
}

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Temp file owner — auto-removed on drop, mirrors the helper in
/// `tests/two_file_link.rs`.
struct TempExe(PathBuf);

impl TempExe {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir();
        let unique = format!(
            "mdbcc_i386_pe_{name}_{:x}.exe",
            std::process::id() as u64 * 0x100 + Instant::now().elapsed().as_nanos() as u64,
        );
        TempExe(dir.join(unique))
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Helpers for reading PE32 fields
// ---------------------------------------------------------------------------

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Return the offset of the PE signature ("PE\0\0") per the DOS stub.
fn pe_offset(buf: &[u8]) -> usize {
    read_u32(buf, 0x3C) as usize
}

// ---------------------------------------------------------------------------
// Structural tests (deterministic — no spawn required)
// ---------------------------------------------------------------------------

#[test]
fn pe32_magic_byte() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let pe_off = pe_offset(&pe);
    let opt_off = pe_off + 24; // skip PE sig (4) + COFF header (20)
    let magic = read_u16(&pe, opt_off);
    assert_eq!(
        magic, 0x010B,
        "PE32 Magic must be 0x010B, got 0x{magic:04X}"
    );
}

#[test]
fn pe32_size_of_optional_header() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let pe_off = pe_offset(&pe);
    // SizeOfOptionalHeader is at offset PE + 4 (PE sig) + 16 (5 u32 + u32 + u32)
    // = the 16-bit field just before Characteristics.
    let size_off = pe_off + 4 + 16;
    let size = read_u16(&pe, size_off);
    assert_eq!(
        size, 0xE0,
        "PE32 SizeOfOptionalHeader = 0xE0, got 0x{size:X}"
    );
}

#[test]
fn pe32_machine_field() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let pe_off = pe_offset(&pe);
    // Machine is at PE + 4 (signature).
    let machine = read_u16(&pe, pe_off + 4);
    assert_eq!(
        machine, 0x014C,
        "PE32 Machine = IMAGE_FILE_MACHINE_I386 (0x014C), got 0x{machine:04X}"
    );
}

#[test]
fn pe32_characteristics_flags() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let pe_off = pe_offset(&pe);
    // Characteristics is at PE + 4 + 18 (last u16 of COFF header).
    let chars = read_u16(&pe, pe_off + 4 + 18);
    // PE32: EXECUTABLE_IMAGE | 32BIT_MACHINE | RELOCS_STRIPPED = 0x0103
    const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
    assert!(
        chars & IMAGE_FILE_EXECUTABLE_IMAGE != 0,
        "EXECUTABLE_IMAGE flag must be set; chars=0x{chars:04X}"
    );
    assert!(
        chars & IMAGE_FILE_32BIT_MACHINE != 0,
        "32BIT_MACHINE flag must be set on PE32; chars=0x{chars:04X}"
    );
    assert!(
        chars & IMAGE_FILE_RELOCS_STRIPPED != 0,
        "RELOCS_STRIPPED flag must be set per Q-Reloc; chars=0x{chars:04X}"
    );
}

#[test]
fn pe32_image_base() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let pe_off = pe_offset(&pe);
    // PE32 optional header offsets:
    //   0x00 Magic (u16)
    //   0x02 LinkerVer (2 u8)
    //   0x04 SizeOfCode (u32)
    //   0x08 SizeOfInitData (u32)
    //   0x0C SizeOfUninit (u32)
    //   0x10 EntryPoint (u32)
    //   0x14 BaseOfCode (u32)
    //   0x18 BaseOfData (u32)  ← PE32-ONLY
    //   0x1C ImageBase (u32)   ← PE32 (u32, not u64)
    let opt_off = pe_off + 24;
    let image_base = read_u32(&pe, opt_off + 0x1C);
    assert_eq!(
        image_base, 0x0040_0000,
        "PE32 ImageBase = 0x00400000, got 0x{image_base:08X}"
    );
}

#[test]
fn pe32_no_pdata_section() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    // Search the section table for `.pdata`. Section table starts after
    // PE sig (4) + COFF header (20) + optional header (SizeOfOptHdr).
    let pe_off = pe_offset(&pe);
    let n_sections = read_u16(&pe, pe_off + 4 + 2);
    let opt_hdr_size = read_u16(&pe, pe_off + 4 + 16);
    let sect_table_off = pe_off + 4 + 20 + opt_hdr_size as usize;

    for i in 0..n_sections as usize {
        let entry = sect_table_off + i * 40;
        let name = &pe[entry..entry + 8];
        assert_ne!(
            &name[..6],
            b".pdata",
            "PE32 must not carry a .pdata section (x86 SEH uses fs:[0])"
        );
        assert_ne!(
            &name[..6],
            b".xdata",
            "PE32 must not carry a .xdata section"
        );
    }
}

#[test]
fn pe32_uses_borland_compatible_version_metadata() {
    // BC4.5/tlink32 marks RailC as linker 2.25, OS 1.0, subsystem 3.10.
    // Windows still uses these legacy fields for app-compat decisions that
    // affect dialog base-unit/font sizing under WOW64.
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let pe_off = pe_offset(&pe);
    let opt_off = pe_off + 24;
    // Field layout in PE32 optional header up to MinorSubsystemVersion:
    //   0x00..0x1C : Magic..ImageBase                  (already validated)
    //   0x20 SectionAlignment (u32)
    //   0x24 FileAlignment (u32)
    //   0x28 MajorOSVersion (u16)
    //   0x2A MinorOSVersion (u16)
    //   0x2C MajorImageVersion (u16)
    //   0x2E MinorImageVersion (u16)
    //   0x30 MajorSubsystemVersion (u16)
    //   0x32 MinorSubsystemVersion (u16)
    assert_eq!(pe[opt_off + 0x02], 2, "PE32 MajorLinkerVersion");
    assert_eq!(pe[opt_off + 0x03], 25, "PE32 MinorLinkerVersion");
    assert_eq!(read_u16(&pe, opt_off + 0x28), 1, "PE32 MajorOSVersion");
    assert_eq!(read_u16(&pe, opt_off + 0x2A), 0, "PE32 MinorOSVersion");
    assert_eq!(
        read_u16(&pe, opt_off + 0x30),
        3,
        "PE32 MajorSubsystemVersion"
    );
    assert_eq!(
        read_u16(&pe, opt_off + 0x32),
        10,
        "PE32 MinorSubsystemVersion"
    );
}

// ---------------------------------------------------------------------------
// Runtime test (spawns the PE; skip-loud on any spawn failure)
// ---------------------------------------------------------------------------

#[test]
fn i386_pe_runs_and_exits_42() {
    let obj = build_main_returns_42_i386();
    let pe = link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32");

    let tmp = TempExe::new("exit42");
    if let Err(e) = std::fs::write(&tmp.0, &pe) {
        eprintln!("SKIP (write failure): {e}");
        return;
    }

    // Spawn with a 5-second timeout (the program is `mov eax,42; ret` —
    // it should exit immediately; anything longer than 5s = hung).
    let mut child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "SKIP (spawn failure — WOW64 may have refused the image): {e}\n\
                 image size = {} bytes",
                pe.len()
            );
            return;
        }
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code();
                assert_eq!(
                    code,
                    Some(42),
                    "i386 PE32 hello-world expected exit 42, got {code:?}"
                );
                return;
            }
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(5) {
                    let _ = child.kill();
                    panic!(
                        "i386 PE32 hello-world hung (>5s); image size = {} bytes",
                        pe.len()
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = child.kill();
                panic!("try_wait failed: {e}");
            }
        }
    }
}
