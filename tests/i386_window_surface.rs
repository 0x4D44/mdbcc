//! Phase D / D1 oracle — the **i386 (PE32)** twin of
//! `tests/win32_window_surface.rs` (S3.12).
//!
//! The full Win32 hello-window surface — `RegisterClassExA` →
//! `CreateWindowExA` → the `GetMessageA`/`TranslateMessage`/`DispatchMessageA`
//! loop → the `__stdcall` `WndProc` callback → `DefWindowProcA` — must compile
//! to a valid **i386 PE32** GUI image whose import table names every USER32
//! symbol. This is the 32-bit analogue of the x64 structural proof and shows
//! S3.11's `emit_win32_call` stdcall path generalises from a single KERNEL32
//! call (`lstrlenA`) to the whole USER32 window surface on i386. It also
//! exercises the intrinsic `<windows.h>` resolving `WINAPI`/`CALLBACK` to
//! `__stdcall` on Win32 (S3.10), so `WinMain` decorates as `_WinMain@16` and
//! the GUI entry stub finds it (the `auto_subsystem` GUI selection below).
//!
//! ## Honesty
//! Structural only — there is no GUI-liveness check here (that is the heavier
//! O6/O17 harness, a separate design decision). This parses the produced PE32
//! bytes directly (machine == 0x14C, optional-header Magic == 0x10B,
//! Subsystem == 2, a `USER32.dll` import descriptor naming the D1 set via
//! 4-byte thunks), so it runs headless with zero external dependencies and
//! never launches anything.
//!
//! ## Why self-contained parse helpers
//! PE32 differs from PE32+ in two ways this test must respect: the data
//! directory sits at optional-header offset 96 (not 112), and Import Lookup
//! Table thunks are 4-byte (not 8). The helpers here are PE32-correct and
//! local, so the x64 goldens in `tests/win32_window_surface.rs` (which guard
//! byte-adjacent behaviour) are left untouched.
#![cfg(windows)]

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, LinkOpts};
use mdbcc::pp::DefaultResolver;
use std::path::PathBuf;

// ---- PE32 structural parsing (4-byte ILT thunks; data dir @ opt+96) -------

fn parse_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn parse_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
/// `e_lfanew` — the PE-signature file offset, read from the DOS header (we do
/// not assume mdbcc's 0x80; we read it so the parser cannot be fooled).
fn pe_off(pe: &[u8]) -> usize {
    parse_u32(pe, 0x3C) as usize
}
fn coff_off(pe: &[u8]) -> usize {
    pe_off(pe) + 4
}
fn opt_off(pe: &[u8]) -> usize {
    coff_off(pe) + 20
}
/// COFF `Machine` (0x14C == `IMAGE_FILE_MACHINE_I386`).
fn machine(pe: &[u8]) -> u16 {
    parse_u16(pe, coff_off(pe))
}
/// `SizeOfOptionalHeader` (COFF header offset 16) — drives the section table
/// location, which is 16 bytes earlier for PE32 than PE32+.
fn sizeof_opt(pe: &[u8]) -> usize {
    parse_u16(pe, coff_off(pe) + 16) as usize
}
/// Optional-header `Magic` (0x10B == PE32, 0x20B == PE32+).
fn opt_magic(pe: &[u8]) -> u16 {
    parse_u16(pe, opt_off(pe))
}
/// `Subsystem` — optional-header offset 68 in *both* PE32 and PE32+ (ImageBase
/// widening 4→8 is exactly offset by PE32+ dropping `BaseOfData`).
fn subsystem(pe: &[u8]) -> u16 {
    parse_u16(pe, opt_off(pe) + 68)
}
/// Import directory RVA — `DataDirectory[1].VirtualAddress`. For PE32 the data
/// directory begins at optional-header offset 96 (PE32+ is 112).
fn import_dir_rva(pe: &[u8]) -> u32 {
    parse_u32(pe, opt_off(pe) + 96 + 8)
}
/// `(raw_ptr, va)` for the named section, read from the image's own table.
fn section(pe: &[u8], name: &[u8]) -> (usize, u32) {
    let nsec = parse_u16(pe, coff_off(pe) + 2) as usize;
    let tbl = opt_off(pe) + sizeof_opt(pe);
    for i in 0..nsec {
        let h = tbl + i * 40;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        if pe[h..h + 8] == want {
            return (parse_u32(pe, h + 20) as usize, parse_u32(pe, h + 12));
        }
    }
    panic!("section {:?} not found", String::from_utf8_lossy(name));
}
/// RVA inside `.idata` → file offset (the section is fully present in the file
/// image; `.idata` RVAs are absolute, no relocs).
fn idata_off(pe: &[u8], rva: u32) -> usize {
    let (ptr, va) = section(pe, b".idata");
    ptr + (rva - va) as usize
}
fn cstr(pe: &[u8], mut o: usize) -> String {
    let mut s = String::new();
    while pe[o] != 0 {
        s.push(pe[o] as char);
        o += 1;
    }
    s
}
/// DLL names appearing in the import directory, in descriptor order.
fn imported_dlls(pe: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva(pe));
    loop {
        let oft = parse_u32(pe, d);
        let name_rva = parse_u32(pe, d + 12);
        let ft = parse_u32(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        out.push(cstr(pe, idata_off(pe, name_rva)));
        d += 20;
    }
    out
}
/// Names under a given DLL descriptor only (PE32: 4-byte ILT thunks; the high
/// bit set means import-by-ordinal, otherwise the thunk is an RVA to the
/// hint/name entry whose 2-byte hint we skip).
fn imported_symbols_of(pe: &[u8], dll: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva(pe));
    loop {
        let oft = parse_u32(pe, d);
        let name_rva = parse_u32(pe, d + 12);
        let ft = parse_u32(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let this_dll = cstr(pe, idata_off(pe, name_rva));
        if this_dll.eq_ignore_ascii_case(dll) {
            let mut t = idata_off(pe, oft);
            loop {
                let thunk = parse_u32(pe, t);
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000 == 0 {
                    out.push(cstr(pe, idata_off(pe, thunk) + 2));
                }
                t += 4;
            }
        }
        d += 20;
    }
    out
}
/// Every imported symbol across all descriptors.
fn imported_symbols(pe: &[u8]) -> Vec<String> {
    imported_dlls(pe)
        .iter()
        .flat_map(|d| imported_symbols_of(pe, d))
        .collect()
}

/// Build `src` to an i386 PE32; the GUI subsystem is auto-selected (a `WinMain`
/// program ⇒ Subsystem 2), exactly as the x64 `compile_to_pe` path does.
fn compile_to_pe32(src: &[u8]) -> Vec<u8> {
    let resolver = DefaultResolver {
        base_dir: PathBuf::from("."),
    };
    let obj = compile_to_object_with_target(src, "<input>", &resolver, TargetKind::Win32)
        .expect("a `<windows.h>` hello-window-surface program must compile (i386 D1)");
    let opts = LinkOpts {
        machine: coff::Machine::I386,
        subsystem: link::auto_subsystem(&obj),
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    };
    link::link_single(&obj, &opts).expect("link i386 PE32")
}

/// The D1 target app — mirrors `PROG_WINDOW_SURFACE` in
/// `tests/win32_window_surface.rs` (kept inline so this i386 test is hermetic
/// and the x64 goldens file is untouched). On i386 `WINAPI`/`CALLBACK` resolve
/// to `__stdcall`, so this also proves the callback (S3.10) and the API-call
/// (S3.11) paths compose across the whole window surface.
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

/// The irreducible D1 USER32 hello-window set — every name must appear as an
/// imported symbol of the i386 GUI program (proving codegen routes each
/// through the IAT via the `emit_win32_call` stdcall path on i386).
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
fn i386_window_surface_compiles_to_gui_pe32_importing_user32_set() {
    let pe = compile_to_pe32(PROG_WINDOW_SURFACE.as_bytes());

    // i386 PE32: COFF machine 0x14C, optional-header Magic 0x10B.
    assert_eq!(
        machine(&pe),
        0x014C,
        "i386 image must have COFF Machine 0x14C"
    );
    assert_eq!(
        opt_magic(&pe),
        0x010B,
        "i386 image must be PE32 (optional-header Magic 0x10B), not PE32+"
    );

    // GUI subsystem (selected by WinMain — same auto_subsystem as x64).
    assert_eq!(
        subsystem(&pe),
        2,
        "a WinMain program with the hello-window USER32 surface must be PE \
         Subsystem == 2 (GUI)"
    );

    // BOTH descriptors present: KERNEL32 (the GUI stub's ExitProcess) and
    // USER32 (the hello-window symbols).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — the D1 USER32 set was not recognised \
         as imports on i386 (got {dlls:?})"
    );

    // Every D1 USER32 symbol must appear under the USER32 descriptor.
    let user32_syms = imported_symbols_of(&pe, "USER32.dll");
    for want in D1_USER32_HELLO_WINDOW {
        assert!(
            user32_syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing from the USER32 descriptor — i386 \
             D1 surface incomplete (got {user32_syms:?})"
        );
    }

    // ExitProcess is still imported (the GUI stub calls it after WinMain).
    let all_syms = imported_symbols(&pe);
    assert!(
        all_syms.iter().any(|s| s == "ExitProcess"),
        "ExitProcess missing — the KERNEL32 import path regressed on i386"
    );
}

/// The console-program invariant on i386: a plain `main` imports **only**
/// KERNEL32 (no USER32 descriptor leaks in when no USER32 symbol is used) —
/// the PE32 mirror of the x64 dormancy guarantee.
#[test]
fn i386_console_program_imports_only_kernel32() {
    let pe = compile_to_pe32(b"int main(void){ return 0; }");
    assert_eq!(machine(&pe), 0x014C);
    assert_eq!(opt_magic(&pe), 0x010B);
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        !dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "a console program must not import USER32 on i386 — got {dlls:?}"
    );
}
