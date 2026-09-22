//! Phase D / D1 oracle: the Win32 hello-window surface (USER32 imports +
//! `<windows.h>` types/constants). Per
//! `wrk_docs/2026.05.18 - HLD - Phase D (minimal OWL runtime).md` §D-a, D1.
//!
//! D1 is the *substrate*: the table/header growth that lets a window
//! program *compile*. **No runtime here** — message loop / WndProc / real
//! window display is D2/D5. So this oracle is **COMPILE + STRUCTURAL** —
//! same shape as `tests/win32_msgbox.rs`:
//!  1. A `#include <windows.h>` program declares `MSG`/`WNDCLASSEXA` locals,
//!     references the new `WM_*`/`WS_*`/`CW_USEDEFAULT`/`SW_*`/`IDC_*`/
//!     `GWLP_*`/`CS_*`/`COLOR_WINDOW` constants, and *calls* (does not run)
//!     RegisterClassExA / CreateWindowExA / GetMessageA / TranslateMessage /
//!     DispatchMessageA / DefWindowProcA / PostQuitMessage / ShowWindow /
//!     UpdateWindow / LoadCursorA / Set/GetWindowLongPtrA. We assert it
//!     COMPILES, PE Subsystem == 2 (GUI; selected by `WinMain`), and the
//!     import directory contains a USER32.dll descriptor with the new
//!     symbols (alongside the unchanged KERNEL32 descriptor).
//!  2. A console program still yields **exactly one** KERNEL32 descriptor,
//!     no USER32 — the byte-identical-console regression, structurally
//!     locked here (the `.idata` golden in `tests/pe_imports.rs` is the
//!     executable proof; this is the same invariant said one way more).
//!
//! Structural, in-process, no external toolchain (mirrors
//! `tests/win32_msgbox.rs` / `tests/pe_imports.rs` conventions).

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

/// `(raw_ptr, vsize, va)` for the named section (read from the produced
/// image's own section table; cannot be fooled by an optimizer).
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

/// RVA inside `.idata` -> file offset (the section is fully present in the
/// file image; RVAs in `.idata` are absolute, no relocs).
fn idata_off(pe: &[u8], rva: u32) -> usize {
    let (ptr, _vsize, va) = section(pe, b".idata");
    ptr + (rva - va) as usize
}

/// DLL names appearing in the import directory, in descriptor order.
fn imported_dlls(pe: &[u8]) -> Vec<String> {
    let opt = PE_OFF + 4 + 20;
    let import_dir_rva = parse_u32(pe, opt + 112 + 8); // data dir [1].VA
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva);
    loop {
        let oft = parse_u32(pe, d);
        let name_rva = parse_u32(pe, d + 12);
        let ft = parse_u32(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
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

/// Every imported symbol (across all descriptors), parsed from each
/// descriptor's ILT.
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

/// Names appearing under a given DLL descriptor only (so we can pin that
/// the new USER32 symbols are in the *USER32* descriptor, not KERNEL32).
fn imported_symbols_of(pe: &[u8], dll: &str) -> Vec<String> {
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
        // Read this descriptor's DLL name.
        let mut o = idata_off(pe, name_rva);
        let mut this_dll = String::new();
        while pe[o] != 0 {
            this_dll.push(pe[o] as char);
            o += 1;
        }
        if this_dll.eq_ignore_ascii_case(dll) {
            let mut t = idata_off(pe, oft);
            loop {
                let thunk = u64::from_le_bytes(pe[t..t + 8].try_into().unwrap());
                if thunk == 0 {
                    break;
                }
                let mut o = idata_off(pe, thunk as u32) + 2;
                let mut s = String::new();
                while pe[o] != 0 {
                    s.push(pe[o] as char);
                    o += 1;
                }
                out.push(s);
                t += 8;
            }
        }
        d += 20;
    }
    out
}

/// The D1 target app: a `<windows.h>` GUI program that declares each new
/// type, references each new constant, and *calls* (does not run — the
/// `WinMain` is never invoked here) every USER32 hello-window symbol.
/// Forces:
///   - the `<windows.h>` struct/typedef/macro additions to PARSE (an unknown
///     type or macro is a hard parse error — the file fails to compile);
///   - each USER32 name to be recognised as a Win32 import via
///     `WIN32_IMPORTS`, so the IAT carries it.
///
/// The body uses a free function `WndProc` as a `WNDPROC` value (Phase A's
/// `&function` -> `RipRef::Func`; CALLBACK is empty so it is the standard
/// Win64 4-arg function signature). No message loop runs (the test does
/// not launch this PE — D2/D5 do that).
const PROG_WINDOW_SURFACE: &str = r#"
#include <windows.h>

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_NCCREATE) {
        CREATESTRUCTA *cs;
        cs = (CREATESTRUCTA *)l;
        SetWindowLongPtrA(h, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
        return DefWindowProcA(h, m, w, l);
    }
    if (m == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {
    WNDCLASSEXA wc;
    MSG msg;
    HWND hwnd;
    LONG_PTR self;

    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hI;
    wc.hIcon = 0;
    wc.hCursor = LoadCursorA(0, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(LONG_PTR)(COLOR_WINDOW + 1);
    wc.lpszMenuName = 0;
    wc.lpszClassName = "MdbccD1";
    wc.hIconSm = 0;
    RegisterClassExA(&wc);

    hwnd = CreateWindowExA(
        0, "MdbccD1", "MDBCC_D1",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        0, 0, hI, 0);
    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);
    self = GetWindowLongPtrA(hwnd, GWLP_USERDATA);

    while (GetMessageA(&msg, 0, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    if (msg.message == WM_QUIT) {
        return (int)msg.wParam + (int)self;
    }
    return 0;
}
"#;

/// A normal console program (the byte-identical path — same as
/// `tests/win32_msgbox.rs`'s `PROG_CONSOLE`).
const PROG_CONSOLE: &str = "int main(void){ return 0; }";

/// Phase D / D1 USER32 hello-window set the surface growth makes
/// recognisable as Win32 imports. The HLD's irreducible set; every name
/// here must appear as an imported symbol of the D1 GUI program above
/// (proving the WIN32_IMPORTS append took, *and* that codegen routes each
/// to the IAT via the unchanged `is_win32_import` / `emit_win32_call`
/// path — no new mechanism).
const D1_USER32_HELLO_WINDOW: &[&str] = &[
    "RegisterClassExA",
    "CreateWindowExA",
    "ShowWindow",
    "UpdateWindow",
    "GetMessageA",
    "TranslateMessage",
    "DispatchMessageA",
    "DefWindowProcA",
    "PostQuitMessage",
    "LoadCursorA",
    "SetWindowLongPtrA",
    "GetWindowLongPtrA",
];

#[test]
fn window_surface_program_compiles_to_gui_pe_importing_user32_set() {
    // The compile-or-die proof: every <windows.h> type the program names
    // (MSG, WNDCLASSEXA, CREATESTRUCTA, HBRUSH, HCURSOR, HICON, HDC,
    // LONG_PTR, WNDPROC) and every constant (WM_*/WS_*/CW_*/SW_*/IDC_*/
    // GWLP_*/CS_*/COLOR_WINDOW) must parse via the intrinsic header
    // additions; every USER32 name must be a recognised Win32 import so
    // the call is emitted through the IAT, not as an unresolved symbol.
    let pe = compile_to_pe(PROG_WINDOW_SURFACE.as_bytes())
        .expect("a `<windows.h>` hello-window-surface program must compile (D1)");

    // GUI subsystem (selected by WinMain — unchanged from C2).
    assert_eq!(
        subsystem(&pe),
        2,
        "a WinMain program with the hello-window USER32 surface must be PE \
         Subsystem == 2 (GUI)"
    );

    // BOTH descriptors present: KERNEL32 (the stub's ExitProcess) and
    // USER32 (the new hello-window symbols).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — the D1 USER32 set was not \
         recognised as imports (got {dlls:?})"
    );

    // Every D1 USER32 hello-window symbol must appear under the USER32
    // descriptor (proves WIN32_IMPORTS append + is_win32_import recognition
    // + emit_win32_call routing for each new name).
    let user32_syms = imported_symbols_of(&pe, "USER32.dll");
    for want in D1_USER32_HELLO_WINDOW {
        assert!(
            user32_syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing from the USER32 descriptor — \
             D1 surface incomplete (got {user32_syms:?})"
        );
    }

    // ExitProcess is still imported (the unchanged KERNEL32 path; the GUI
    // stub calls it).
    let all_syms = imported_symbols(&pe);
    assert!(
        all_syms.iter().any(|s| s == "ExitProcess"),
        "ExitProcess missing — the KERNEL32 import path regressed"
    );
}

#[test]
fn console_program_has_exactly_one_kernel32_descriptor_no_user32_after_d1() {
    // The central D1 regression, structurally: a console program must
    // still yield **exactly one** import descriptor (KERNEL32), with
    // USER32 absent and none of the D1 USER32 names imported. Appending
    // the hello-window USER32 set to WIN32_IMPORTS must stay dormant
    // unless a program actually references those symbols. (The
    // byte-identical `.idata` proof is `tests/pe_imports.rs`; this is the
    // same invariant said structurally one level up.)
    let pe = compile_to_pe(PROG_CONSOLE.as_bytes()).expect("compile console");
    assert_eq!(
        subsystem(&pe),
        3,
        "console program must stay subsystem 3 after D1"
    );

    let dlls = imported_dlls(&pe);
    assert_eq!(
        dlls.len(),
        1,
        "console program must have exactly one import descriptor after \
         D1, got {dlls:?}"
    );
    assert!(
        dlls[0].eq_ignore_ascii_case("KERNEL32.dll"),
        "the sole descriptor must be KERNEL32.dll, got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    for forbidden in D1_USER32_HELLO_WINDOW {
        assert!(
            !syms.iter().any(|s| s == forbidden),
            "USER32 symbol '{forbidden}' must NOT be imported by a console \
             program (got {syms:?}) — D1's WIN32_IMPORTS appends must stay \
             dormant unless referenced"
        );
    }
}
