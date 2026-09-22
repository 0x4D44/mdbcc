//! Phase C / C3 oracle: intrinsic `<windows.h>` + `MessageBoxA`/USER32.
//!
//! C3 makes a basic Win32 GUI app *compile*: `#include <windows.h>` resolves
//! to a minimal intrinsic typedef/macro body (so `HINSTANCE`/`LPSTR`/`WINAPI`/
//! `UINT`/`MB_OK` parse), and `MessageBoxA` is recognised by name in codegen
//! as a USER32 import (the same way libc names are special-cased), emitted as
//! an indirect `call [rip+IAT]` with the Win64 4-arg ABI.
//!
//! C3 is **COMPILE + STRUCTURAL only**. A `MessageBoxA` shows a *modal* dialog
//! and blocks, so it is deliberately NOT headless-runnable; the live
//! launch/probe/dismiss is C4 / O6. This file proves, structurally, that the
//! emitted PE is well-formed: subsystem 2 (GUI) and an `.idata` that imports
//! `MessageBoxA` from `USER32.dll` *in addition to* the unchanged KERNEL32
//! descriptor. It also re-asserts (structurally) the central Phase-C
//! invariant: a console program still yields **exactly one** KERNEL32
//! descriptor (USER32 absent) — `MessageBoxA` is dormant unless referenced.
//!
//! Structural, in-process, no external toolchain (mirrors `tests/pe_imports.rs`
//! / `tests/winmain.rs`).

#![cfg(windows)]

use mdbcc::compile_to_pe;

const PE_OFF: usize = 0x80;
const SIZEOF_OPT: usize = 0xF0;
const SECT_HDR_LEN: usize = 40;

fn parse_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn parse_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// The PE optional header's `Subsystem` (`u16` at optional-header offset 68).
fn subsystem(pe: &[u8]) -> u16 {
    parse_u16(pe, PE_OFF + 4 + 20 + 68)
}

/// `(raw_ptr, vsize, va)` for the section named `name`, read from the produced
/// image's own section table (cannot be fooled by an optimizer).
fn section(pe: &[u8], name: &[u8]) -> (usize, u32, u32) {
    let coff = PE_OFF + 4;
    let nsec = parse_u16(pe, coff + 2) as usize;
    let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
    for i in 0..nsec {
        let h = tbl + i * SECT_HDR_LEN;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        if pe[h..h + 8] == want {
            return (
                parse_u32(pe, h + 20) as usize, // PointerToRawData
                parse_u32(pe, h + 8),           // VirtualSize
                parse_u32(pe, h + 12),          // VirtualAddress
            );
        }
    }
    panic!("section {:?} not found", String::from_utf8_lossy(name));
}

/// Map an RVA inside `.idata` to a file offset (the section is fully present
/// in the file image; RVAs in `.idata` are absolute, no relocs).
fn idata_off(pe: &[u8], rva: u32) -> usize {
    let (ptr, _vsize, va) = section(pe, b".idata");
    ptr + (rva - va) as usize
}

/// The DLL names appearing in the import directory, in descriptor order.
/// Parses `IMAGE_IMPORT_DESCRIPTOR`s from `dirs[1]` (offset 0x80 + 4 + 20 +
/// 112; data dir 1 is at optional-header offset 112 + 1*8) until the
/// all-zero null terminator. Each descriptor's `Name` (offset +12) is an RVA
/// to a NUL-terminated DLL string.
fn imported_dlls(pe: &[u8]) -> Vec<String> {
    let opt = PE_OFF + 4 + 20;
    let import_dir_rva = parse_u32(pe, opt + 112 + 8); // data directory [1].VA
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva);
    loop {
        let oft = parse_u32(pe, d);
        let name_rva = parse_u32(pe, d + 12);
        let ft = parse_u32(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break; // null terminator
        }
        let mut o = idata_off(pe, name_rva);
        let mut s = String::new();
        while pe[o] != 0 {
            s.push(pe[o] as char);
            o += 1;
        }
        out.push(s);
        d += 20;
    }
    out
}

/// Every imported symbol name (across all descriptors), parsed from each
/// descriptor's ILT (`OriginalFirstThunk`): a NUL-terminated array of 8-byte
/// by-name thunks, each an RVA to `<hint:u16><name><NUL>`.
fn imported_symbols(pe: &[u8]) -> Vec<String> {
    let opt = PE_OFF + 4 + 20;
    let import_dir_rva = parse_u32(pe, opt + 112 + 8);
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva);
    loop {
        let oft = parse_u32(pe, d);
        let name_rva = parse_u32(pe, d + 12);
        let ft = parse_u32(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let mut t = idata_off(pe, oft);
        loop {
            let thunk = u64::from_le_bytes(pe[t..t + 8].try_into().unwrap());
            if thunk == 0 {
                break;
            }
            let mut o = idata_off(pe, thunk as u32) + 2; // skip hint
            let mut s = String::new();
            while pe[o] != 0 {
                s.push(pe[o] as char);
                o += 1;
            }
            out.push(s);
            t += 8;
        }
        d += 20;
    }
    out
}

/// The C3 target app: a `#include <windows.h>` GUI program whose `WinMain`
/// (declared with the intrinsic `WINAPI`/`HINSTANCE`/`LPSTR` from the header)
/// calls `MessageBoxA`. It is NOT run here (the dialog is modal/blocking —
/// that is C4/O6); we only assert it *compiles* to a well-formed PE.
const PROG_MSGBOX: &str = r#"
#include <windows.h>
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {
    MessageBoxA(0, "hi", "t", 0);
    return 0;
}
"#;

/// A `<windows.h>`-using program that also names the MB_* constants and the
/// other intrinsic typedefs, to prove the minimal header body parses.
const PROG_TYPES: &str = r#"
#include <windows.h>
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {
    UINT t;
    DWORD d;
    BOOL b;
    HWND w;
    HMENU m;
    LPCSTR s;
    WPARAM wp;
    LPARAM lp;
    LRESULT lr;
    t = MB_OK | MB_ICONINFORMATION;
    d = MB_OKCANCEL;
    b = MB_ICONERROR;
    w = 0;
    m = 0;
    s = "x";
    wp = 0;
    lp = 0;
    lr = MessageBoxA(w, s, "cap", t);
    return (int)lr + (int)d + (int)b;
}
"#;

/// A normal console program (the unchanged, byte-identical path).
const PROG_CONSOLE: &str = "int main(void){ return 0; }";

/// S5 (railc W5): CTL3D is a legacy decoration DLL. Native Win64 builds should
/// be able to use a source-built compatibility definition instead of importing
/// CTL3D32.dll, which is not present on modern 64-bit Windows.
const PROG_CTL3D: &str = r#"
#include <windows.h>
extern "C" int Ctl3dRegister(HINSTANCE) { return 1; }
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {
    return Ctl3dRegister(hI) ? 0 : 1;
}
"#;

#[test]
fn msgbox_program_compiles_to_gui_pe_importing_user32() {
    let pe = compile_to_pe(PROG_MSGBOX.as_bytes())
        .expect("a <windows.h> MessageBoxA WinMain program must compile");

    // Structural: GUI subsystem (C2 selects it from WinMain).
    assert_eq!(
        subsystem(&pe),
        2,
        "a WinMain MessageBoxA program must be PE Subsystem == 2 (GUI)"
    );

    // The import directory must contain BOTH a KERNEL32 descriptor
    // (unchanged — the entry stub still calls ExitProcess) AND a USER32
    // descriptor (newly pulled in by the MessageBoxA reference).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing (the stub's ExitProcess) — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — MessageBoxA was not recognised as a \
         USER32 import (got {dlls:?})"
    );

    // And MessageBoxA must actually be one of the imported symbols.
    let syms = imported_symbols(&pe);
    assert!(
        syms.iter().any(|s| s == "MessageBoxA"),
        "MessageBoxA not present in any descriptor's ILT — got {syms:?}"
    );
    // ExitProcess is still imported (the unchanged KERNEL32 path).
    assert!(
        syms.iter().any(|s| s == "ExitProcess"),
        "ExitProcess missing — the KERNEL32 import path regressed"
    );
}

#[test]
fn intrinsic_windows_h_typedefs_and_mb_constants_parse() {
    // Compiles iff the intrinsic <windows.h> body declares every named
    // typedef (UINT/DWORD/BOOL/HWND/HMENU/LPCSTR/WPARAM/LPARAM/LRESULT) and
    // the MB_* object macros (MB_OK/MB_OKCANCEL/MB_ICONINFORMATION/
    // MB_ICONERROR). A missing typedef => `expected a type`; a missing macro
    // => `undeclared MB_*`. Either way this fails to compile.
    let pe = compile_to_pe(PROG_TYPES.as_bytes())
        .expect("the intrinsic <windows.h> body must parse all C3 types/macros");
    assert_eq!(subsystem(&pe), 2, "still a GUI program");
    let syms = imported_symbols(&pe);
    assert!(
        syms.iter().any(|s| s == "MessageBoxA"),
        "MessageBoxA import missing in the types program"
    );
}

#[test]
fn console_program_has_exactly_one_kernel32_descriptor_no_user32() {
    // The byte-identical-console regression, asserted structurally: a console
    // program must still yield exactly ONE descriptor (KERNEL32), with USER32
    // absent and MessageBoxA never imported. `MessageBoxA` in WIN32_IMPORTS
    // must stay dormant unless a program actually references it.
    let pe = compile_to_pe(PROG_CONSOLE.as_bytes()).expect("compile console");
    assert_eq!(subsystem(&pe), 3, "console program must stay subsystem 3");

    let dlls = imported_dlls(&pe);
    assert_eq!(
        dlls.len(),
        1,
        "console program must have exactly one import descriptor, got {dlls:?}"
    );
    assert!(
        dlls[0].eq_ignore_ascii_case("KERNEL32.dll"),
        "the sole descriptor must be KERNEL32.dll, got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    assert!(
        !syms.iter().any(|s| s == "MessageBoxA"),
        "MessageBoxA must NOT be imported by a console program (got {syms:?}) \
         — adding it to WIN32_IMPORTS must not perturb the console path"
    );
}

#[test]
fn ctl3d_program_can_use_source_built_definition_without_legacy_dll_import() {
    let pe =
        compile_to_pe(PROG_CTL3D.as_bytes()).expect("a Ctl3dRegister WinMain program must compile");
    assert_eq!(
        subsystem(&pe),
        2,
        "WinMain program must be GUI (subsystem 2)"
    );

    let dlls = imported_dlls(&pe);
    assert!(
        !dlls.iter().any(|d| d.eq_ignore_ascii_case("CTL3D32.dll")),
        "source-built Ctl3dRegister must not pull CTL3D32.dll, got {dlls:?}"
    );
    let syms = imported_symbols(&pe);
    assert!(
        !syms.iter().any(|s| s == "Ctl3dRegister"),
        "source-built Ctl3dRegister must not be imported by name, got {syms:?}"
    );

    // A console program that never names a CTL3D symbol must also stay free of
    // the legacy DLL.
    let con = compile_to_pe(PROG_CONSOLE.as_bytes()).expect("compile console");
    assert!(
        !imported_dlls(&con)
            .iter()
            .any(|d| d.eq_ignore_ascii_case("CTL3D32.dll")),
        "CTL3D32.dll must stay dormant for a program that does not use it"
    );
}
