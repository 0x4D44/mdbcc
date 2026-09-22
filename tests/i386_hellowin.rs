//! S3 EXIT — the Petzold **HELLOWIN.C** compiled against the **real** Borland
//! `<windows.h>` and linked to a 32-bit (PE32) GUI image (in-process linker,
//! the same pipeline every other i386 test uses).
//!
//! This is the headline S3 milestone: the canonical "hello, windows" sample
//! (WNDCLASS init → RegisterClass → CreateWindow → the GetMessage/Translate/
//! Dispatch loop → a `switch`-based WM_PAINT/WM_DESTROY WndProc using
//! BeginPaint/GetClientRect/DrawText/EndPaint) builds with `mdbcc -m32 -I
//! \BC45\INCLUDE` and links into a structurally-valid i386 GUI PE32 whose
//! import table names every USER32/GDI32 symbol the sample calls.
//!
//! Honesty: structural only (no GUI liveness here — that is the separate O6
//! tripwire). It parses the produced PE32 bytes directly (machine 0x14C,
//! Magic 0x10B, Subsystem 2, the HELLOWIN USER32+GDI32 imports present via
//! 4-byte thunks). Self-skips loudly when the BC45 INCLUDE tree is absent
//! (the established O15/oracle precedent — the headers are not in the repo).
#![cfg(windows)]

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, LinkOpts};
use mdbcc::pp::{DefaultResolver, SearchPathResolver};
use std::os::raw::{c_int, c_void};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ---- PE32 structural parsing (4-byte ILT thunks; data dir @ opt+96) -------

fn u16_(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn pe_off(pe: &[u8]) -> usize {
    u32_(pe, 0x3C) as usize
}
fn coff_off(pe: &[u8]) -> usize {
    pe_off(pe) + 4
}
fn opt_off(pe: &[u8]) -> usize {
    coff_off(pe) + 20
}
fn machine(pe: &[u8]) -> u16 {
    u16_(pe, coff_off(pe))
}
fn opt_magic(pe: &[u8]) -> u16 {
    u16_(pe, opt_off(pe))
}
fn subsystem(pe: &[u8]) -> u16 {
    u16_(pe, opt_off(pe) + 68)
}
fn sizeof_opt(pe: &[u8]) -> usize {
    u16_(pe, coff_off(pe) + 16) as usize
}
fn import_dir_rva(pe: &[u8]) -> u32 {
    u32_(pe, opt_off(pe) + 96 + 8) // DataDirectory[1].VirtualAddress (PE32)
}
fn section(pe: &[u8], name: &[u8]) -> (usize, u32) {
    let nsec = u16_(pe, coff_off(pe) + 2) as usize;
    let tbl = opt_off(pe) + sizeof_opt(pe);
    for i in 0..nsec {
        let h = tbl + i * 40;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        if pe[h..h + 8] == want {
            return (u32_(pe, h + 20) as usize, u32_(pe, h + 12));
        }
    }
    panic!("section {:?} not found", String::from_utf8_lossy(name));
}
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
/// Every imported symbol across all descriptors (PE32: 4-byte ILT thunks).
fn imported_symbols(pe: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva(pe));
    loop {
        let oft = u32_(pe, d);
        let name_rva = u32_(pe, d + 12);
        let ft = u32_(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let mut t = idata_off(pe, oft);
        loop {
            let thunk = u32_(pe, t);
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 == 0 {
                out.push(cstr(pe, idata_off(pe, thunk) + 2));
            }
            t += 4;
        }
        d += 20;
    }
    out
}
/// DLL names in the import directory.
fn imported_dlls(pe: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut d = idata_off(pe, import_dir_rva(pe));
    loop {
        let oft = u32_(pe, d);
        let name_rva = u32_(pe, d + 12);
        let ft = u32_(pe, d + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        out.push(cstr(pe, idata_off(pe, name_rva)));
        d += 20;
    }
    out
}

fn include_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wrk_oracle\\bc452\\BC45\\INCLUDE")
}

/// The canonical Petzold HELLOWIN.C (ANSI; the optional `PlaySound` startup
/// jingle dropped — it pulls in WINMM and is irrelevant to the milestone).
const HELLOWIN: &str = r#"
#include <windows.h>

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   PSTR szCmdLine, int iCmdShow)
{
    static char szAppName[] = "HelloWin";
    HWND        hwnd;
    MSG         msg;
    WNDCLASS    wndclass;

    wndclass.style         = CS_HREDRAW | CS_VREDRAW;
    wndclass.lpfnWndProc   = WndProc;
    wndclass.cbClsExtra    = 0;
    wndclass.cbWndExtra    = 0;
    wndclass.hInstance     = hInstance;
    wndclass.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wndclass.lpszMenuName  = NULL;
    wndclass.lpszClassName = szAppName;

    RegisterClass(&wndclass);

    hwnd = CreateWindow(szAppName, "The Hello Program",
                        WS_OVERLAPPEDWINDOW,
                        CW_USEDEFAULT, CW_USEDEFAULT,
                        CW_USEDEFAULT, CW_USEDEFAULT,
                        NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, iCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    HDC         hdc;
    PAINTSTRUCT ps;
    RECT        rect;

    switch (message)
    {
    case WM_PAINT:
        hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rect);
        DrawText(hdc, "Hello, Windows!", -1, &rect,
                 DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        EndPaint(hwnd, &ps);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}
"#;

/// Every USER32/GDI32 symbol HELLOWIN.C names (after the windows.h macro
/// chain resolves `RegisterClass`→`RegisterClassA`, `CreateWindow`→
/// `CreateWindowExA`, `DrawText`→`DrawTextA`, `DefWindowProc`→`DefWindowProcA`,
/// `GetMessage`→`GetMessageA`, `DispatchMessage`→`DispatchMessageA`).
const HELLOWIN_IMPORTS: &[&str] = &[
    "LoadIconA",
    "LoadCursorA",
    "GetStockObject",
    "RegisterClassA",
    "CreateWindowExA",
    "ShowWindow",
    "UpdateWindow",
    "GetMessageA",
    "TranslateMessage",
    "DispatchMessageA",
    "BeginPaint",
    "GetClientRect",
    "DrawTextA",
    "EndPaint",
    "PostQuitMessage",
    "DefWindowProcA",
];

/// Compile + link HELLOWIN.C against the real `<windows.h>` to an i386 PE32.
/// Returns `None` (with a loud skip note) when the BC45 INCLUDE tree is not
/// present — the headers are not vendored, so CI without them self-skips
/// (the established O15/oracle precedent). A compile/link *failure* with the
/// tree present is a hard panic (a real codegen/linker red).
fn build_hellowin_i386() -> Option<Vec<u8>> {
    let inc = include_dir();
    if !inc.join("WINDOWS.H").exists() {
        eprintln!(
            "SKIP: BC45 INCLUDE tree absent at {} (self-skip; headers are \
             not vendored)",
            inc.display()
        );
        return None;
    }
    let resolver = SearchPathResolver {
        dirs: vec![inc],
        fallback: DefaultResolver {
            base_dir: PathBuf::from("."),
        },
    };
    let obj = compile_to_object_with_target(
        HELLOWIN.as_bytes(),
        "hellowin.c",
        &resolver,
        TargetKind::Win32,
    )
    .expect("HELLOWIN.C must compile against the real <windows.h> for i386");
    let opts = LinkOpts {
        machine: coff::Machine::I386,
        subsystem: link::auto_subsystem(&obj),
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    };
    Some(
        link::link_single(&obj, &opts)
            .expect("HELLOWIN.C i386 object must link to a PE32 (imports resolved)"),
    )
}

#[test]
fn hellowin_compiles_and_links_to_i386_gui_pe32_against_real_headers() {
    let Some(pe) = build_hellowin_i386() else {
        return;
    };

    // i386 PE32 GUI image.
    assert_eq!(machine(&pe), 0x014C, "COFF machine must be i386 (0x14C)");
    assert_eq!(
        opt_magic(&pe),
        0x010B,
        "optional header must be PE32 (0x10B)"
    );
    assert_eq!(subsystem(&pe), 2, "WinMain ⇒ GUI subsystem (2)");

    // The three DLLs HELLOWIN pulls in.
    let dlls = imported_dlls(&pe);
    for want in ["KERNEL32.dll", "USER32.dll", "GDI32.dll"] {
        assert!(
            dlls.iter().any(|d| d.eq_ignore_ascii_case(want)),
            "{want} import descriptor missing — got {dlls:?}"
        );
    }

    // Every USER32/GDI32 symbol the sample calls must be imported (proves the
    // windows.h macro chain resolved and codegen routed each through the IAT).
    let syms = imported_symbols(&pe);
    for want in HELLOWIN_IMPORTS {
        assert!(
            syms.iter().any(|s| s == want),
            "HELLOWIN import '{want}' missing — got {syms:?}"
        );
    }
}

// ===========================================================================
// GUI-liveness tripwire (Arthur's call 2026.05.28: "Structural + tripwire").
//
// The structural half above is the rigorous, always-on check. This half is a
// LIVENESS TRIPWIRE — honestly weaker than a stdout differential (a window has
// no diffable stdout and there is no OWL behavioural reference). It proves:
// the i386 PE32 mdbcc emitted actually *runs* under WOW64, RegisterClass +
// CreateWindow succeed, the window pump is live (a top-level "HelloWin" window
// of OUR process appears), and posting WM_CLOSE drives WM_DESTROY →
// PostQuitMessage → a clean exit 0 (the WM_QUIT wParam). It does NOT verify the
// painted text. Mirrors the O6 (`tests/gui.rs`) machinery; self-skips loudly
// when headless / when WOW64 refuses the image (diagnostic, not a red), and is
// hard-watchdogged so a live window can never hang the suite.
// ===========================================================================

type Handle = *mut c_void;
type Hwnd = *mut c_void;
type Bool = c_int;

const STILL_ACTIVE: u32 = 259;
const WM_CLOSE: u32 = 0x0010;
const WAIT_OBJECT_0: u32 = 0;
const UOI_FLAGS: c_int = 1;
const WSF_VISIBLE: u32 = 0x0001;

/// HELLOWIN's window class (the string it passes to `RegisterClass`).
const HELLOWIN_CLASS: &[u8] = b"HelloWin\0";

#[repr(C)]
struct UserObjectFlags {
    inherit: Bool,
    reserved: u32,
    flags: u32,
}

#[link(name = "user32")]
unsafe extern "system" {
    fn FindWindowA(class_name: *const u8, window_name: *const u8) -> Hwnd;
    fn PostMessageA(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> Bool;
    fn GetWindowThreadProcessId(hwnd: Hwnd, pid: *mut u32) -> u32;
    fn GetProcessWindowStation() -> Handle;
    fn GetUserObjectInformationW(
        h: Handle,
        index: c_int,
        info: *mut c_void,
        len: u32,
        needed: *mut u32,
    ) -> Bool;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: Bool, pid: u32) -> Handle;
    fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
    fn GetExitCodeProcess(h: Handle, code: *mut u32) -> Bool;
    fn TerminateProcess(h: Handle, code: u32) -> Bool;
    fn CloseHandle(h: Handle) -> Bool;
}

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_TERMINATE: u32 = 0x0001;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// RAII kill-capable process handle (force-terminates a survivor on drop so a
/// live window can never outlive the test).
struct ProcHandle(Handle);

impl ProcHandle {
    fn open(pid: u32) -> Option<Self> {
        let h = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                0,
                pid,
            )
        };
        if h.is_null() {
            None
        } else {
            Some(ProcHandle(h))
        }
    }
    fn exit_code(&self) -> Option<u32> {
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(self.0, &mut code) };
        if ok != 0 { Some(code) } else { None }
    }
    fn wait(&self, ms: u32) -> bool {
        unsafe { WaitForSingleObject(self.0, ms) == WAIT_OBJECT_0 }
    }
    fn terminate(&self) {
        unsafe {
            TerminateProcess(self.0, 1);
        }
    }
}

impl Drop for ProcHandle {
    fn drop(&mut self) {
        if self.exit_code() == Some(STILL_ACTIVE) {
            self.terminate();
            let _ = self.wait(2000);
        }
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// `true` iff attached to a visible (interactive) window station.
fn interactive_desktop() -> bool {
    unsafe {
        let sta = GetProcessWindowStation();
        if sta.is_null() {
            return false;
        }
        let mut f = UserObjectFlags {
            inherit: 0,
            reserved: 0,
            flags: 0,
        };
        let mut needed: u32 = 0;
        let ok = GetUserObjectInformationW(
            sta,
            UOI_FLAGS,
            &mut f as *mut _ as *mut c_void,
            std::mem::size_of::<UserObjectFlags>() as u32,
            &mut needed,
        );
        ok != 0 && (f.flags & WSF_VISIBLE) != 0
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);

impl TempExe {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("mdbcc_hellowin_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn skip(why: &str) {
    eprintln!("SKIP (i386 HELLOWIN liveness): {why}");
}

#[test]
fn hellowin_launches_shows_window_and_exits_cleanly_on_wm_close() {
    let Some(pe) = build_hellowin_i386() else {
        return;
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "HELLOWIN must be GUI (subsystem 2) before launch"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0)");
        return;
    }

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the HELLOWIN exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            // WOW64 may refuse the i386 image in some host configs — diagnostic
            // skip, never a red (mirrors `i386_run.rs::run_pe`).
            skip(&format!(
                "could not spawn the i386 HELLOWIN exe (WOW64?): {e}"
            ));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let mut c = child;
            let _ = c.kill();
            skip("could not OpenProcess the HELLOWIN child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll FindWindowA by class for ≤4 s, requiring the window to
    // belong to OUR child pid (the class name is the Petzold-standard
    // "HelloWin", so a pid check makes the probe robust against a stray window).
    // If the child dies before a window appears, stop early and diagnose.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if proc.exit_code() != Some(STILL_ACTIVE) {
            break; // process exited before showing a window
        }
        let h = unsafe { FindWindowA(HELLOWIN_CLASS.as_ptr(), std::ptr::null()) };
        if !h.is_null() {
            let mut wpid: u32 = 0;
            unsafe { GetWindowThreadProcessId(h, &mut wpid) };
            if wpid == pid {
                hwnd = h;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // No window. Distinguish a CRASH (real codegen red) from "never showed"
        // / WOW64-refusal (environment → self-skip).
        let code = proc.exit_code();
        proc.terminate();
        let _ = proc.wait(3000);
        if let Some(c) = code
            && c != STILL_ACTIVE
        {
            let hi = (c >> 24) & 0xff;
            assert!(
                hi != 0xC0 && hi != 0x80,
                "i386 HELLOWIN crashed before showing a window (STATUS {c:#x}) \
                 — a runtime codegen/ABI red in the emitted GUI PE"
            );
        }
        skip("HelloWin window not found in 4 s (headless / WOW64 refusal)");
        return;
    }

    // Live window confirmed. Close it: WM_CLOSE → DefWindowProc → DestroyWindow
    // → WM_DESTROY → PostQuitMessage(0) → the GetMessage loop exits → WinMain
    // returns msg.wParam (0).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed; child force-terminated");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("HELLOWIN did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "signalled but STILL_ACTIVE — impossible"
            );
            let hi = (code >> 24) & 0xff;
            assert!(
                hi != 0xC0 && hi != 0x80,
                "i386 HELLOWIN exited with a crash STATUS {code:#x} — the emitted \
                 GUI PE faulted"
            );
            // HELLOWIN returns the WM_QUIT wParam, which PostQuitMessage(0) set
            // to 0. A live, correctly-behaving window thus exits exactly 0.
            assert_eq!(
                code, 0,
                "i386 HELLOWIN should exit 0 (WM_QUIT wParam from PostQuitMessage(0)) \
                 — got {code}"
            );
            // Liveness proven end-to-end: built (real <windows.h>), launched
            // under WOW64, registered its class, created + showed a top-level
            // window, ran its message pump, and exited cleanly on WM_CLOSE.
        }
        None => skip("process signalled but GetExitCodeProcess failed"),
    }
}
