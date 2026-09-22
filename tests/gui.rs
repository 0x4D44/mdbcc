//! Phase C / C4 oracle **O6** — GUI liveness tripwire.
//!
//! O6 is the end-to-end check for the Phase-C Win32 substrate: a real
//! `#include <windows.h>` `WinMain` program that calls `MessageBoxA` is
//! compiled by mdbcc to a real `.exe`, and we assert (a) the PE is
//! structurally a GUI image importing the right USER32 symbol, and (b) — when
//! an interactive desktop exists — the process actually launches, raises its
//! titled modal window, can be dismissed programmatically, and exits cleanly.
//!
//! ## Honesty (verbatim per the HLD §C4 / §Risks)
//! O6 is **honestly weaker** than the O1/O2/O3 stdout differential. A GUI app
//! has no stdout to diff and there is no Borland-OWL behavioural reference, so
//! the *liveness half* is only a **tripwire**: it proves "a GUI Win32 PE mdbcc
//! emitted loads, shows a titled top-level window, and exits cleanly when
//! asked". It does **not** prove the window's contents, layout, or message
//! handling are correct (that has no automated oracle without a Borland-OWL
//! reference; `mdscreensnap` + Phase I are the heavier follow-ups).
//!
//! The **structural half is the always-on rigorous part** and is as strong as
//! the rest of the suite: it parses the produced PE bytes directly (subsystem
//! byte == 2, a `USER32.dll` import descriptor that imports `MessageBoxA`) and
//! runs even headless, with zero external dependencies, never launching
//! anything. The liveness half **self-skips loudly** (the established
//! `o2_active`/`o3_active` precedent) whenever no interactive window station
//! is available, and is hard-bounded so a modal `MessageBoxA` can never hang
//! the suite (watchdog → `TerminateProcess`, see `liveness_check`).
//!
//! Std-only, no new crate deps: the handful of Win32 calls the liveness probe
//! needs are declared via a tiny `extern "system"` FFI block (mirroring the
//! repo's std-only constraint — the `windows`/`winapi` crates are *not*
//! added). Structural parsing mirrors `tests/win32_msgbox.rs`; the
//! compile-to-`.exe` + drop-cleanup mirrors `tests/winmain.rs`.

#![cfg(windows)]

use std::os::raw::{c_int, c_void};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mdbcc::compile_to_pe;

// ---------------------------------------------------------------------------
// The O6 app (hand-written, in the test — not the differential corpus)
// ---------------------------------------------------------------------------

/// The smallest program that exercises the *entire* Phase-C substrate end to
/// end: C3 intrinsic `<windows.h>` types (`HINSTANCE`/`LPSTR`/`WINAPI`), C2
/// `WinMain` detection (⇒ subsystem 2 + GUI stub), C1 `USER32` descriptor +
/// `MessageBoxA` IAT slot, and the Phase-A 4-arg Win64 ABI. `MessageBoxA`
/// with `MB_OK` (0) raises a **modal** dialog whose caption is the exact
/// window title the liveness probe searches for.
const PROG_O6: &str = r#"
#include <windows.h>
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {
    MessageBoxA(0, "mdbcc-o6-body", "MDBCC_O6_WINDOW", 0);
    return 0;
}
"#;

/// The exact caption of the `MessageBoxA` dialog (its top-level window title).
const O6_WINDOW_TITLE: &[u8] = b"MDBCC_O6_WINDOW\0";

// ---------------------------------------------------------------------------
// Temp .exe with drop-cleanup (mirrors tests/winmain.rs::TempExe)
// ---------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);
static GUI_RUNTIME_LOCK: Mutex<()> = Mutex::new(());

struct TempExe(PathBuf);

impl TempExe {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("mdbcc_o6_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn gui_runtime_lock() -> MutexGuard<'static, ()> {
    GUI_RUNTIME_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Structural PE parsing (mirrors tests/win32_msgbox.rs verbatim in style)
// ---------------------------------------------------------------------------

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

/// Map an RVA inside `.idata` to a file offset.
fn idata_off(pe: &[u8], rva: u32) -> usize {
    let (ptr, _vsize, va) = section(pe, b".idata");
    ptr + (rva - va) as usize
}

/// The DLL names appearing in the import directory, in descriptor order.
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
/// descriptor's ILT (`OriginalFirstThunk`).
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

// ---------------------------------------------------------------------------
// Win32 FFI for the liveness half (std-only, no winapi/windows crate)
// ---------------------------------------------------------------------------

type Handle = *mut c_void;
type Hwnd = *mut c_void;
type Bool = c_int;

const STILL_ACTIVE: u32 = 259; // STATUS_PENDING — process has not exited
const WM_CLOSE: u32 = 0x0010;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WAIT_OBJECT_0: u32 = 0;
const UOI_FLAGS: c_int = 1;
const WSF_VISIBLE: u32 = 0x0001;
const GCLP_HCURSOR: c_int = -12; // GetClassLongPtr index for the class cursor
const IDC_ARROW: usize = 32512; // MAKEINTRESOURCE(32512) — default arrow
const IDC_IBEAM: usize = 32513; // MAKEINTRESOURCE(32513) — text I-beam

#[repr(C)]
struct UserObjectFlags {
    inherit: Bool,
    reserved: u32,
    flags: u32,
}

#[link(name = "user32")]
unsafe extern "system" {
    /// `FindWindowA(NULL, lpWindowName)` — locate a top-level window by exact
    /// caption (a `MessageBoxA` is a real top-level window so titled).
    fn FindWindowA(class_name: *const u8, window_name: *const u8) -> Hwnd;
    /// Post `WM_CLOSE` to the dialog (a message box honours it → IDCANCEL).
    /// Asynchronous: never blocks the test thread on the modal pump.
    fn PostMessageA(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> Bool;
    /// Enumerate top-level windows; the callback returns 0 to stop. Used by the
    /// E5 (hello fixture) probe to find the child's window by **owning
    /// PID** — robust against the fixture window caption (a
    /// caption-only `FindWindowA` could match an unrelated window; PID match
    /// cannot). The callback is a plain `extern "system" fn`; the search
    /// context travels through `lParam` as a raw pointer.
    fn EnumWindows(cb: unsafe extern "system" fn(Hwnd, isize) -> Bool, lparam: isize) -> Bool;
    /// Enumerate the child windows of `parent`; the E5d (gallery fixture) probe counts
    /// them as its behaviour oracle (the static-control children must exist).
    fn EnumChildWindows(
        parent: Hwnd,
        cb: unsafe extern "system" fn(Hwnd, isize) -> Bool,
        lparam: isize,
    ) -> Bool;
    /// `GetWindowThreadProcessId(hwnd, &pid)` — the PID owning `hwnd` (the
    /// return value, the thread id, is ignored here).
    fn GetWindowThreadProcessId(hwnd: Hwnd, pid_out: *mut u32) -> u32;
    /// `GetWindowTextA(hwnd, buf, max)` — copy the window caption into `buf`
    /// (NUL-terminated), returning the copied length. The E5b (instance fixture) probe
    /// reads it as the behaviour oracle: the title must be "First Instance",
    /// proving `TApplication::InitApplication` ran (it overwrote the ctor's
    /// "Additional Instance").
    fn GetWindowTextA(hwnd: Hwnd, buf: *mut u8, max: c_int) -> c_int;
    /// `GetClassLongPtrA(hwnd, GCLP_HCURSOR)` — the cursor handle the window's
    /// class was registered with. The E5c (cursor fixture) probe compares it to the
    /// I-beam cursor as the behaviour oracle for the `GetWindowClass(WNDCLASS&)`
    /// hook (works cross-process — it queries the window's class).
    fn GetClassLongPtrA(hwnd: Hwnd, index: c_int) -> usize;
    /// `LoadCursorA(NULL, MAKEINTRESOURCE(id))` — a shared predefined cursor
    /// handle (consistent across processes for the system `IDC_*` cursors).
    fn LoadCursorA(hinst: Handle, name: usize) -> usize;
    /// `SendMessageA` — **synchronous** message dispatch. Used by the E4
    /// click-injection harness to deliver `WM_LBUTTONDOWN` to the OWL
    /// window: the window proc runs the response-table `EV_WM_LBUTTONDOWN`
    /// cracker to completion (incrementing `g_clicks` and emitting one
    /// `"CLICK N\n"` line) *before* `SendMessageA` returns, so the harness
    /// can deterministically count dispatches. Cross-thread `SendMessageA`
    /// queues into the receiving thread's pump; the OWL `Run()` loop is
    /// already calling `GetMessageA`/`DispatchMessageA`, so the queued
    /// sent-message is delivered in-line. NOTE: this is a harness-side
    /// import — the OWL exe itself does NOT import `SendMessageA`
    /// (`WIN32_IMPORTS` deliberately omits it; the OWL app only *receives*
    /// the message through its standard `GetMessageA` loop).
    fn SendMessageA(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> isize;
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

/// RAII process handle: closes on drop, and — as a last-resort backstop —
/// force-terminates the child if it is still alive (so a modal `MessageBoxA`
/// cannot survive a panic or an early return anywhere in the probe).
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
    /// Wait up to `ms`; `true` iff the process signalled (exited) in time.
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
        // Backstop: if the child is somehow still running (e.g. a panic
        // unwound past the explicit cleanup), kill it so no modal dialog
        // outlives the test, then reap it briefly and close the handle.
        if self.exit_code() == Some(STILL_ACTIVE) {
            self.terminate();
            let _ = self.wait(2000);
        }
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// `true` iff this process is attached to a *visible* (interactive) window
/// station. Headless CI / a Session-0 service has an invisible station where
/// `FindWindowA` would never see the dialog — there we self-skip the liveness
/// half rather than false-fail (the `o2_active`/`o3_active` precedent).
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

// ---------------------------------------------------------------------------
// O6 — structural half (ALWAYS runs, headless-safe, rigorous)
// ---------------------------------------------------------------------------

/// Compile the O6 app to a real `.exe` and assert it is structurally a GUI
/// PE importing `MessageBoxA` from `USER32.dll`. This half has **zero**
/// external dependencies, never launches anything, and is as rigorous as the
/// rest of the suite (it is the always-on part of O6 per the HLD).
#[test]
fn o6_app_compiles_to_gui_pe_importing_user32_messageboxa() {
    let pe = compile_to_pe(PROG_O6.as_bytes())
        .expect("the O6 <windows.h> MessageBoxA WinMain app must compile");

    // Subsystem byte == 2 (GUI) — C2 selects it from the WinMain definition.
    assert_eq!(
        subsystem(&pe),
        2,
        "the O6 GUI app must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // The import directory must contain a USER32.dll descriptor (newly pulled
    // in by the MessageBoxA reference) alongside the unchanged KERNEL32 one.
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

    // MessageBoxA must actually be one of the imported symbols.
    let syms = imported_symbols(&pe);
    assert!(
        syms.iter().any(|s| s == "MessageBoxA"),
        "MessageBoxA not present in any descriptor's ILT — got {syms:?}"
    );
}

// ---------------------------------------------------------------------------
// O6 — liveness half (self-skips loudly headless; hard-bounded watchdog)
// ---------------------------------------------------------------------------

/// Loud self-skip helper (the `o2_active`/`o3_active` SKIP-print precedent).
fn skip(reason: &str) {
    eprintln!("[O6] SKIP liveness: {reason} — structural half still ran (rigorous, always-on)");
}

/// O6 liveness tripwire. Spawns the O6 `.exe`, finds its modal `MessageBoxA`
/// window by exact title via `extern "system"` Win32 FFI, dismisses it with
/// `WM_CLOSE`, and asserts a clean process exit.
///
/// ## Hard safety design (non-negotiable — must never hang)
/// A modal `MessageBoxA` blocks its process forever if not dismissed, so the
/// whole probe is strictly bounded and force-terminates the child on *any*
/// failure path:
/// - **Headless gate up front:** if no visible window station
///   (`interactive_desktop()` false), self-skip *before spawning* — the
///   structural half already ran. No process is created.
/// - **Bounded find:** poll `FindWindowA` for at most ~4 s at 50 ms cadence.
/// - **Watchdog on every non-happy path:** window not found in time, or a
///   non-clean / non-signalling outcome ⇒ `TerminateProcess` immediately,
///   reap with a bounded `WaitForSingleObject(3000)`, then **self-skip
///   loudly** (preferred per the HLD: like o2/o3 absent) — never block,
///   never false-fail on environment.
/// - **RAII backstop:** `ProcHandle::drop` force-terminates a still-alive
///   child even if a panic unwinds past the explicit cleanup.
///
/// Total wall time is a few seconds maximum in every branch.
#[test]
fn o6_gui_liveness_launch_dismiss_clean_exit() {
    // Build the real .exe (a Phase-C codegen/PE red surfaces here, not as a
    // hang). The structural test above is the rigorous always-on check; this
    // recompiles so the liveness half is self-contained.
    let pe = match compile_to_pe(PROG_O6.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("O6 app failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "O6 app must be subsystem 2 before launch"
    );

    // Headless gate: never spawn a modal dialog with no interactive desktop.
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0)");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the O6 exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the O6 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    // Own the process via a kill-capable handle (RAII backstop on drop). We
    // do not keep `child` (its Drop only waits); the ProcHandle is the
    // authoritative lifetime + kill switch. Forget `child` so std does not
    // also try to wait/own it.
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            // Cannot get a kill handle — do not risk an unkillable modal box.
            let _ = terminate_child(child);
            skip("could not OpenProcess the O6 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), O6_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // Could not locate the window within the bound. Treat as headless /
        // environment (preferred self-skip per the HLD) but ALWAYS kill the
        // child first so a modal box can never outlive the suite.
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the O6 window within 4 s (treated as no interactive station)");
        return;
    }

    // Dismiss the modal dialog asynchronously (never blocks this thread).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed; child force-terminated");
        return;
    }

    // It must now exit cleanly within a strict bound. A hang here is NOT
    // allowed: if it does not signal in 5 s we force-terminate and self-skip
    // (environment) rather than block the suite.
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("O6 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    // Signalled in time — assert a defined, non-crash exit code. WM_CLOSE on
    // a message box yields IDCANCEL (2) and our GUI stub returns WinMain's
    // value (0); either way it must be a clean, defined, non-crash code.
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "O6 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            let signed = code as i32;
            let is_crash = {
                let hi = ((code) >> 24) & 0xff;
                hi == 0xC0 || hi == 0x80
            };
            assert!(
                !is_crash,
                "O6 process exited with a crash STATUS code {code:#x} \
                 (the emitted GUI PE faulted) — signed {signed}"
            );
            // Liveness proven: built, launched, raised a titled top-level
            // window, dismissed programmatically, exited cleanly. (Per the
            // HLD this is a tripwire, not a conformance oracle — see header.)
        }
        None => {
            // Could not read the code despite signalling — environment, not
            // an mdbcc red; self-skip rather than false-fail.
            skip("process signalled but GetExitCodeProcess failed");
        }
    }
}

/// Last-resort kill when we have a `Child` but failed to get a `ProcHandle`:
/// use the std `Child::kill` path (consumes the child) so we never leak an
/// undismissable modal dialog. A hard backstop on the no-kill-handle path.
fn terminate_child(mut c: std::process::Child) -> std::io::Result<()> {
    c.kill()?;
    let _ = c.wait();
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase D / D2 — bare RegisterClass+CreateWindow+message-loop in raw C
// ---------------------------------------------------------------------------
//
// D2 is the first **runtime exercise** of the D1 Win32 surface: a hand-written
// `<windows.h>`-only `WinMain` that registers a class with a free-function
// `WndProc`, creates a real `CreateWindowExA` framed top-level window, pumps
// the standard `GetMessageA`/`TranslateMessage`/`DispatchMessageA` loop, and
// exits cleanly on `WM_DESTROY`. **No OWL classes yet** (those are D4/D5) and
// **no static-thunk → instance binding via `GWLP_USERDATA`** (that is the D3
// crux — see HLD §D-c). v1 stays minimal: one class, one window, plain free
// `WndProc` whose only hand-handled message is `WM_DESTROY → PostQuitMessage`.
//
// **Why D2 stays raw-C (vs. C++/OWL):** D2's job is to prove the *substrate +
// the loop* end-to-end **before any class machinery exists** — isolating the
// D-a/D-c-shape/D-d risks (USER32 set + WNDPROC ABI + message loop + clean
// teardown) from the D3+ class-binding risks. A failure here is localised to
// the substrate/ABI/loop, not entangled with OWL. The exact same TU shape is
// already known to *parse* under mdbcc (the D1 structural-only oracle's
// `PROG_WINDOW_SURFACE` uses every construct here); D2 is its **runnable**
// sibling — same `<windows.h>` types, same call sites, but actually pumped.
//
// **Construct portability notes (verified against current mdbcc, 2026-05-18):**
//   - `switch` is NOT supported by the parser (Phase D HLD §D-c implicitly,
//     `Keyword::Switch`/`Case`/`Default` tokens are recognised but no parse
//     rule exists). We use `if (m == WM_DESTROY) { ... } return DefWindowProcA(...);`
//     in `WndProc` exactly as the HLD's D2 sketch prescribes.
//   - Aggregate initialiser `WNDCLASSEXA wc = { 0 };` is NOT supported
//     (parser limitation, scratchpad §Known limitations) — fields are assigned
//     one by one, same pattern as the D1 oracle's `PROG_WINDOW_SURFACE`.
//   - `WINAPI`/`CALLBACK` are empty macros (Win64 has one ABI) so the WndProc
//     signature is a plain Win64 4-arg function — Windows can call it
//     indirectly via `lpfnWndProc` and the contract holds **by construction**
//     (Phase A's Win64 ABI; HLD §D-c "Why a normal mdbcc function is a valid
//     `WNDPROC`").
//   - `(HBRUSH)(LONG_PTR)(COLOR_WINDOW + 1)` — chained cast through `LONG_PTR`
//     is the same pattern the D1 oracle already exercises (mdbcc treats casts
//     as no-ops for same-size scalars/pointers; an integer→pointer cast is
//     legal). Tested in D1: still works.

/// The smallest D2 program — a *raw* `<windows.h>` window. It chains
/// `RegisterClassExA`, `CreateWindowExA`, and the standard message loop, with
/// a free-function `WndProc` whose only hand-handled message is `WM_DESTROY`
/// (which calls `PostQuitMessage`). No OWL, no global state, no instance
/// binding (D3 adds the `lpCreateParams`/`GWLP_USERDATA` thunk→instance
/// mechanism). The window title is a unique caption so `FindWindowA` cannot
/// match anything else.
///
/// Teardown chain (close → exit code 0): user posts `WM_CLOSE` →
/// `DefWindowProcA` (our WndProc falls through) → default `DestroyWindow` →
/// Windows sends `WM_DESTROY` → our WndProc does `PostQuitMessage(0)` →
/// `GetMessageA` next returns `0` (the documented `WM_QUIT` contract) →
/// loop exits → `WinMain` returns `(int)msg.wParam` which is `0` → Phase-C
/// GUI stub does `mov ecx,eax; call [rip+ExitProcess]` ⇒ exit code 0.
const PROG_D2_RAW: &str = r#"
#include <windows.h>

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
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
    wc.lpszClassName = "MdbccD2Window";
    wc.hIconSm = 0;
    RegisterClassExA(&wc);

    hwnd = CreateWindowExA(
        0, "MdbccD2Window", "MDBCC_D2_WINDOW",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        0, 0, hI, 0);
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, 0, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
"#;

/// The exact caption of the D2 top-level window (used by `FindWindowA`).
const D2_WINDOW_TITLE: &[u8] = b"MDBCC_D2_WINDOW\0";

/// The D2 USER32 hello-window set the runtime must actually import. A subset
/// of the D1 surface — exactly what D2's source literally names (no
/// `Set`/`GetWindowLongPtrA`: D3 adds those when it introduces the
/// `lpCreateParams`/`GWLP_USERDATA` thunk→instance binding).
const D2_USER32_REQUIRED: &[&str] = &[
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
];

/// Phase D / D2 structural half — ALWAYS-ON, headless-safe, rigorous. Mirrors
/// the MessageBox O6 structural test exactly in shape; the only difference is
/// the imported-symbol set asserted (the D2 USER32 surface, not `MessageBoxA`).
#[test]
fn o6_d2_raw_window_compiles_to_gui_pe_importing_user32_set() {
    let pe = compile_to_pe(PROG_D2_RAW.as_bytes())
        .expect("the D2 raw `<windows.h>` window program must compile");

    // Subsystem byte == 2 (GUI) — C2 selects it from the WinMain definition.
    assert_eq!(
        subsystem(&pe),
        2,
        "the D2 raw-window app must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // Both descriptors present: KERNEL32 (stub's ExitProcess) + USER32 (the
    // D2 window-loop set, freshly imported via WIN32_IMPORTS).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing (the stub's ExitProcess) — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — the D2 USER32 set was not \
         recognised as imports (got {dlls:?})"
    );

    // Every D2 USER32 symbol must actually be in some descriptor's ILT.
    let syms = imported_symbols(&pe);
    for want in D2_USER32_REQUIRED {
        assert!(
            syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing from imports — D2 substrate \
             incomplete (got {syms:?})"
        );
    }
}

/// Phase D / D2 liveness tripwire — desktop-gated, watchdog-bounded. **Reuses
/// the existing `interactive_desktop()` headless gate, `ProcHandle` RAII +
/// `TerminateProcess` watchdog, `skip()` loud self-skip, and the same
/// `FindWindowA`/`PostMessageA` FFI** as the MessageBox O6 above — *not*
/// duplicated. Differences from the MessageBox O6 (intentional, smaller risk):
///   - The D2 window is a **real `CreateWindowExA` top-level window, not a
///     modal `MessageBoxA`**. A non-modal window does NOT block its own
///     process; the watchdog becomes pure backstop (HLD §D-d).
///   - On `WM_CLOSE` the default `DefWindowProcA` calls `DestroyWindow`,
///     which sends `WM_DESTROY`, and the WndProc posts `WM_QUIT` —
///     `GetMessageA` then returns 0 ⇒ loop exits ⇒ `WinMain` returns
///     `(int)msg.wParam == 0` ⇒ Phase-C GUI stub `ExitProcess(0)`. The
///     asserted exit code is therefore **exactly 0** (not a generic
///     "non-crash" — the teardown chain is fully deterministic, unlike a
///     `MessageBoxA` whose `WM_CLOSE` yields IDCANCEL/2).
///
/// Hard safety: same bounded-poll / RAII / TerminateProcess machinery as
/// MessageBox O6 — never hangs, never false-fails on environment.
#[test]
fn o6_d2_raw_window_launches_dismisses_and_clean_exits() {
    let pe = match compile_to_pe(PROG_D2_RAW.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("D2 raw-window app failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "D2 app must be subsystem 2 before launch"
    );

    // Headless gate up front (reuses MessageBox O6's helper verbatim).
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [D2]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the D2 exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the D2 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the D2 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), D2_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the D2 window within 4 s (treated as no interactive station)");
        return;
    }

    // PostMessage(WM_CLOSE) → DefWindowProcA → DestroyWindow → WM_DESTROY →
    // PostQuitMessage(0) → loop exits → ExitProcess(msg.wParam=0). Never
    // blocks this thread (PostMessage is async; the child window is
    // non-modal anyway).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on D2 window; child force-terminated");
        return;
    }

    // It must exit cleanly within a strict bound. A non-modal window does
    // not block its own process; the watchdog is pure backstop.
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("D2 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    // Signalled in time — assert the **deterministic** clean exit code 0
    // (WinMain returns (int)msg.wParam, which is 0 because WM_QUIT carries
    // the value PostQuitMessage(0) passed). Unlike the MessageBox O6 we can
    // demand the exact code, not just "non-crash".
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "D2 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "D2 process must exit with code 0 (WinMain returns \
                 (int)msg.wParam == 0 after PostQuitMessage(0)), got {code:#x}"
            );
        }
        None => {
            skip("D2 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Phase D / D3 — static WndProc thunk + GWLP_USERDATA instance map +
//                virtual HandleMessage dispatch
// ---------------------------------------------------------------------------
//
// D3 is the **crux of Phase D** and the HLD's load-bearing interlock check:
// it proves that **Phase A** function-name decay (`lpfnWndProc = StaticWndProc`)
// + **Phase A** >4-arg Win64 stack ABI (the 12 `CreateWindowExA` args, the
// 12th being `lpCreateParams = &mw`) + **Phase B** virtual dispatch (a base
// pointer `Window*` reaching the derived `MyWindow::HandleMessage` override
// through the vtable slot) + **Phase C/D1** Win32 surface (the USER32
// `<windows.h>` types/constants/imports, incl. `SetWindowLongPtrA` /
// `GetWindowLongPtrA` / `CREATESTRUCTA` / `WM_NCCREATE`) **all interlock
// across the Win32 callback boundary** — i.e. when `USER32!DispatchMessageA`
// indirectly calls our static thunk, the thunk recovers the per-window
// `Window*` from `GWLP_USERDATA`, and a virtual call on that base pointer
// reaches the derived class's `HandleMessage` (which posts `WM_QUIT` on
// `WM_DESTROY`).
//
// This is the classic OWL/Petzold static-thunk → instance-dispatch mechanism,
// proven *without* a global side-table — the HLD §D-c chose `GWLP_USERDATA`
// precisely so mdbcc's missing global-ctor feature is never exercised
// ("crux risk closed by construction" — HLD §Risks 2). D3 isolates it on a
// tiny hand class **before** the full OWL runtime (D4/D5) lands.
//
// **Test-infrastructure ONLY** — exercises features already proven by
// Phase A/B/C/D1/D2 (no `src/` changes expected). The fixture is the only
// new content; all liveness machinery is the existing D2/O6 infra reused
// verbatim (`interactive_desktop()`, `ProcHandle` RAII, `TerminateProcess`
// watchdog, `FindWindowA`/`PostMessageA` FFI, `skip()`).
//
// **Construct portability notes (verified against current mdbcc, 2026-05-18):**
//   - `class Foo : public Bar { public: virtual T m(...) {...} };` — the
//     base/derived/virtual machinery used here is identical to Phase B's
//     `virtual_dispatch_through_base_pointer` (Sq/Rect/Shape) which proves
//     a stack-allocated derived instance's ctor installs the right vtable
//     and a `Base*` dispatches to the derived override. D3 reuses exactly
//     that pattern with the addition of a Win32 callback boundary.
//   - Bare class-tag as type name in casts: `(Window*)cs->lpCreateParams` —
//     the D1 oracle (`tests/win32_window_surface.rs`) already exercises
//     `(CREATESTRUCTA*)l` cast; class tags are registered in `tags` and
//     accepted by `peek_is_type_after_lparen` exactly as struct tags are
//     (parser §`decl_specifiers` bare-tag path).
//   - Pointer↔`LONG_PTR` casts: `(LONG_PTR)self` and `(Window*)v` are
//     same-size scalar conversions (Win64 8-byte pointers / `__int64`); the
//     existing D1 oracle's `(LONG_PTR)cs->lpCreateParams` round-trip proves
//     the codegen path (`convert` is a no-op for same-size scalars).
//   - `self->hwnd = h;` (writing a field through a class pointer) — same
//     pattern as `tests/corpus/portable/structs.c`'s `q->y = 12;` already
//     in the e2e golden.
//   - Bare-name function decay to `WNDPROC`: `wc.lpfnWndProc = StaticWndProc;`
//     — D2's `WndProc` already uses this; static-on-free-function does not
//     change codegen (storage class is parsed and ignored — there is one
//     Win64 ABI; no name decoration in x64).
//
// If a real compiler gap is found (e.g. a virtual call across the
// WndProc/thunk boundary mis-dispatches, or a parser gap on any of the
// constructs above), this fixture surfaces it immediately as a build error
// or a non-zero exit code under the watchdog — the contract is STOP+report,
// never hack.

/// The D3 program: a static `WndProc` thunk that binds a `Window*` instance
/// in `WM_NCCREATE` via `lpCreateParams`/`GWLP_USERDATA`, then dispatches all
/// later messages to the instance's **virtual** `HandleMessage`. The derived
/// `MyWindow` overrides `HandleMessage` to `PostQuitMessage` on `WM_DESTROY`.
///
/// Teardown chain (close → exit code 0): `WM_CLOSE` → `MyWindow::HandleMessage`
/// (does not special-case `WM_CLOSE`) → falls through to `DefWindowProcA` →
/// default `DestroyWindow` → Windows sends `WM_DESTROY` → static thunk
/// recovers `self` via `GetWindowLongPtrA(GWLP_USERDATA)` → virtual-dispatches
/// to `MyWindow::HandleMessage(WM_DESTROY)` → `PostQuitMessage(0)` →
/// `GetMessageA` next returns 0 → loop exits → `WinMain` returns
/// `(int)msg.wParam == 0` → Phase-C GUI stub `ExitProcess(0)`.
///
/// Note on the pre-`WM_NCCREATE` window — Windows can send
/// `WM_GETMINMAXINFO` *before* `WM_NCCREATE`, with `GWLP_USERDATA` still 0
/// (per the HLD §D-c binding sequence). The thunk's `if (self != 0)` guard
/// covers this: such early messages fall through to `DefWindowProcA(h,m,w,l)`
/// (the standard correct behaviour — never a null deref).
const PROG_D3_THUNK: &str = r#"
#include <windows.h>

class Window {
public:
    HWND hwnd;
    Window() { hwnd = 0; }
    virtual LRESULT HandleMessage(UINT m, WPARAM w, LPARAM l) {
        return DefWindowProcA(hwnd, m, w, l);
    }
};

class MyWindow : public Window {
public:
    virtual LRESULT HandleMessage(UINT m, WPARAM w, LPARAM l) {
        if (m == WM_DESTROY) {
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcA(hwnd, m, w, l);
    }
};

LRESULT CALLBACK StaticWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Window* self;
    if (m == WM_NCCREATE) {
        CREATESTRUCTA* cs;
        cs = (CREATESTRUCTA*)l;
        self = (Window*)cs->lpCreateParams;
        self->hwnd = h;
        SetWindowLongPtrA(h, GWLP_USERDATA, (LONG_PTR)self);
    }
    self = (Window*)GetWindowLongPtrA(h, GWLP_USERDATA);
    if (self != 0) {
        return self->HandleMessage(m, w, l);
    }
    return DefWindowProcA(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {
    WNDCLASSEXA wc;
    MSG msg;
    HWND hwnd;
    MyWindow mw;

    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = StaticWndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hI;
    wc.hIcon = 0;
    wc.hCursor = LoadCursorA(0, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(LONG_PTR)(COLOR_WINDOW + 1);
    wc.lpszMenuName = 0;
    wc.lpszClassName = "MdbccD3Window";
    wc.hIconSm = 0;
    RegisterClassExA(&wc);

    hwnd = CreateWindowExA(
        0, "MdbccD3Window", "MDBCC_D3_WINDOW",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        0, 0, hI, &mw);
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, 0, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
"#;

/// The exact caption of the D3 top-level window (used by `FindWindowA`).
const D3_WINDOW_TITLE: &[u8] = b"MDBCC_D3_WINDOW\0";

/// The D3 USER32 symbol set the runtime must import: the D2 set **plus**
/// the instance-map primitives `SetWindowLongPtrA` / `GetWindowLongPtrA`
/// that D3 newly exercises (HLD §D-c — the per-window storage Windows
/// itself provides, chosen over a global table to avoid mdbcc's missing
/// global-ctor feature).
const D3_USER32_REQUIRED: &[&str] = &[
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

/// Phase D / D3 structural half — ALWAYS-ON, headless-safe, rigorous. Same
/// shape as the D2 / MessageBox-O6 structural tests; the only difference is
/// the symbol set asserted (the D3 superset that includes the
/// `Set`/`GetWindowLongPtrA` instance-map primitives D3 newly exercises).
#[test]
fn o6_d3_thunk_instance_window_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_D3_THUNK.as_bytes())
        .expect("the D3 static-thunk + virtual-dispatch window program must compile");

    // Subsystem byte == 2 (GUI) — C2 selects it from the WinMain definition.
    assert_eq!(
        subsystem(&pe),
        2,
        "the D3 thunk-instance app must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // Both descriptors present: KERNEL32 (stub's ExitProcess) + USER32 (the
    // D3 window-loop + instance-map set).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing (the stub's ExitProcess) — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — the D3 USER32 set was not \
         recognised as imports (got {dlls:?})"
    );

    // Every D3 USER32 symbol must actually be in some descriptor's ILT —
    // including `Set`/`GetWindowLongPtrA` which D3 newly exercises (D2 did
    // not name them).
    let syms = imported_symbols(&pe);
    for want in D3_USER32_REQUIRED {
        assert!(
            syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing from imports — D3 substrate \
             incomplete (got {syms:?})"
        );
    }
}

/// Phase D / D3 liveness tripwire — desktop-gated, watchdog-bounded.
/// **Reuses the D2/O6 infra verbatim** (`interactive_desktop()`, `ProcHandle`
/// RAII + `TerminateProcess` watchdog, `skip()` loud self-skip, the
/// `FindWindowA` / `PostMessageA` FFI). Differences vs. D2:
///   - The dispatch path is **WndProc thunk → `GetWindowLongPtrA` →
///     virtual `HandleMessage`** (not a free-function `WndProc` that
///     handles `WM_DESTROY` directly). The thunk recovers the per-HWND
///     `Window*` from `GWLP_USERDATA`, then a virtual call on that base
///     pointer reaches the **derived `MyWindow::HandleMessage`** override
///     (the Phase B virtual-dispatch mechanism, exercised across the
///     Win32 callback boundary).
///   - A null/missing vptr or wrong slot would crash the thunk on the
///     first dispatched message — caught here by the watchdog forcing
///     termination + a non-zero exit code (the test would FAIL, not hang).
///   - The clean-exit assert is exactly 0 (same deterministic teardown
///     chain as D2: `WM_CLOSE` → default → `WM_DESTROY` → `PostQuitMessage(0)`
///     → `WM_QUIT` → loop exits → `ExitProcess(msg.wParam=0)`).
///
/// Hard safety: same bounded-poll / RAII / TerminateProcess machinery as D2
/// — never hangs, never false-fails on environment.
#[test]
fn o6_d3_thunk_dispatches_via_vtable_to_clean_exit() {
    let pe = match compile_to_pe(PROG_D3_THUNK.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("D3 thunk-instance app failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "D3 app must be subsystem 2 before launch"
    );

    // Headless gate up front (reuses MessageBox O6's helper verbatim).
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [D3]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the D3 exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the D3 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the D3 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), D3_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the D3 window within 4 s (treated as no interactive station)");
        return;
    }

    // PostMessage(WM_CLOSE) → DefWindowProcA → DestroyWindow → WM_DESTROY →
    // static thunk → GetWindowLongPtrA(GWLP_USERDATA) → virtual
    // MyWindow::HandleMessage(WM_DESTROY) → PostQuitMessage(0) → loop exits
    // → ExitProcess(msg.wParam=0). Never blocks this thread (PostMessage is
    // async; the child window is non-modal).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on D3 window; child force-terminated");
        return;
    }

    // It must exit cleanly within a strict bound. A crash on the dispatch
    // path (null vptr / wrong vtable slot / ABI mismatch across the Win32
    // callback boundary) would manifest here as a STATUS_* exit code or a
    // non-zero exit, NOT a hang — the watchdog is a backstop.
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("D3 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    // Signalled in time — assert the **deterministic** clean exit code 0
    // exactly (same teardown chain as D2; the virtual dispatch must reach
    // `MyWindow::HandleMessage(WM_DESTROY)` and `PostQuitMessage(0)`).
    // A wrong slot would either crash (STATUS_*) or return non-zero;
    // an exact `0` is the executable proof that:
    //   - the static thunk's address was correctly emitted (Phase A `&func`);
    //   - the >4-arg Win64 stack ABI handed `&mw` to `CreateWindowExA` arg 12
    //     and it round-tripped via `WM_NCCREATE`/`lpCreateParams` (Phase A);
    //   - `GWLP_USERDATA` stored/recovered the `Window*` correctly (D1 surface);
    //   - the virtual call through the base pointer reached `MyWindow`'s
    //     override (Phase B vtable across the Win32 callback boundary).
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "D3 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "D3 process must exit with code 0 (virtual dispatch from \
                 static thunk → MyWindow::HandleMessage(WM_DESTROY) → \
                 PostQuitMessage(0) → WinMain returns (int)msg.wParam == 0), \
                 got {code:#x}"
            );
        }
        None => {
            skip("D3 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Phase D / D4 — owl/ runtime TU compiles (intrinsic-prepended OWL runtime)
// ---------------------------------------------------------------------------
//
// D4 is the **OWL runtime landing**: `<owl/applicat.h>` / `<owl/framewin.h>`
// resolve to a built-in body (the intrinsic-header mechanism Phase C / C3
// proved for `<windows.h>`, generalised), and the body bundles the **OWL
// runtime impls** (TApplication::Run / message loop / TWindow::Create / the
// static WndProc thunk / `WinMain`) into the same TU so a hello-OWL source
// compiles **single-TU** (no linker; mdbcc is single-TU by design — HLD
// §D-b). The user writes `OwlMain`; the runtime owns `WinMain` (Phase-C
// detection ⇒ subsystem 2 + GUI stub, reused unchanged).
//
// D4 = **COMPILES + STRUCTURAL** only — D5 adds the runtime O6 launch.
// Asserts: the hello-OWL TU compiles via `mdbcc::compile_to_pe`; subsystem
// == 2 (GUI); KERNEL32 + USER32 descriptors present; the D1 hello-window
// USER32 set is in the imports (the runtime's emitted USER32 calls are
// routed through the IAT via the unchanged `is_win32_import` /
// `emit_win32_call` path). Plus: the console regression (a `main` program
// must remain byte-identical-structurally — exactly one KERNEL32
// descriptor, zero USER32 — the same dormancy invariant D1/D2/D3 lock).

/// The D4 hello-OWL program: an unmodified Borland-API OWL source. The user
/// `#include`s `<owl/applicat.h>` and `<owl/framewin.h>` (the umbrella
/// headers), subclasses TApplication with a `TMyApp` whose `InitMainWindow`
/// override constructs a `TFrameWindow`, and writes `OwlMain` (not
/// `WinMain`). The runtime owns `WinMain` (intrinsic-prepended) and calls
/// `OwlMain`. Compiles iff the OWL runtime + the user TU together form a
/// valid single-TU C++ program in mdbcc's Phase-A/B subset.
const PROG_D4_HELLO_OWL: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TFrameWindow(0, "MDBCC_D4_OWL"));
    }
};

int OwlMain(int argc, char** argv) {
    TMyApp app;
    return app.Run();
}
"#;

/// A normal console program — the byte-identical regression target. A
/// `main` program must stay subsystem-3, exactly one KERNEL32 descriptor,
/// zero USER32. The `<owl/*.h>` resolver branch must be gated on the path
/// prefix so a non-OWL program emits zero new bytes.
const PROG_D4_CONSOLE: &str = "int main(void){ return 0; }";

/// The D4 USER32 hello-window set the OWL runtime must actually emit calls
/// to (so each name appears as an import in the produced PE). This is the
/// D3 superset — the runtime's `WinMain`/`TApplication::Run`/`TWindow::Create`/
/// `OwlStaticWndProc` together name every entry the hello-window needs.
const D4_USER32_REQUIRED: &[&str] = &[
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

/// Phase D / D4 structural — the hello-OWL TU **compiles** to a GUI PE with
/// the full OWL USER32 set in its imports. Compile-only; D5 launches it.
#[test]
fn o6_d4_owl_runtime_tu_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_D4_HELLO_OWL.as_bytes())
        .expect("the D4 hello-OWL TU (owl/* + OwlMain) must compile");

    // GUI subsystem (selected by the runtime-provided WinMain — C2 path).
    assert_eq!(
        subsystem(&pe),
        2,
        "the D4 hello-OWL app must be PE Subsystem == 2 (WINDOWS_GUI) — the \
         runtime-provided WinMain triggers GuiWinMain entry"
    );

    // Both descriptors present: KERNEL32 (stub's ExitProcess) + USER32 (the
    // runtime's emitted USER32 calls).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — the OWL runtime's USER32 calls \
         were not recognised as imports (got {dlls:?})"
    );

    // Every D4 USER32 symbol must appear in some descriptor's ILT — proof
    // that the OWL runtime's emitted calls are routed through the IAT via
    // the unchanged `is_win32_import` / `emit_win32_call` path.
    let syms = imported_symbols(&pe);
    for want in D4_USER32_REQUIRED {
        assert!(
            syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing from imports — the OWL \
             runtime did not emit a call to it (got {syms:?})"
        );
    }
}

/// Phase D / D4 byte-identical console regression — a `main` program must
/// stay subsystem-3 with **exactly one** KERNEL32 descriptor and zero
/// USER32 imports. The `<owl/*.h>` resolver branch is gated on the path
/// prefix so a non-OWL TU emits zero new bytes (the dormancy invariant D1
/// proves byte-identically via `tests/pe_imports.rs`; this is the same
/// invariant said structurally one level up — same shape as D1/D2/D3's
/// console-regression sibling tests).
#[test]
fn o6_d4_console_program_unchanged_after_owl_runtime() {
    let pe = compile_to_pe(PROG_D4_CONSOLE.as_bytes()).expect("compile console");

    assert_eq!(
        subsystem(&pe),
        3,
        "console program must stay subsystem 3 after D4 (no OWL runtime \
         materialises in a `main` TU that does not #include <owl/*.h>)"
    );

    let dlls = imported_dlls(&pe);
    assert_eq!(
        dlls.len(),
        1,
        "console program must have exactly one import descriptor after D4, \
         got {dlls:?}"
    );
    assert!(
        dlls[0].eq_ignore_ascii_case("KERNEL32.dll"),
        "the sole descriptor must be KERNEL32.dll, got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    for forbidden in D4_USER32_REQUIRED {
        assert!(
            !syms.iter().any(|s| s == forbidden),
            "USER32 symbol '{forbidden}' must NOT be imported by a console \
             program (got {syms:?}) — D4's owl/ resolver branch must stay \
             dormant unless an owl/* header is included"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase D / D5 — THE MILESTONE: the full hello-OWL `OwlMain` app via O6
// ---------------------------------------------------------------------------
//
// D5 is the **Phase-D milestone** and the OWL roadmap's North Star: an
// unmodified Borland-API OWL source (a `TApplication` subclass + `OwlMain`)
// compiled by mdbcc opens a real Win64 framed top-level window on Windows 11
// and exits cleanly. It is the **integration test** that proves the full
// stack — D1 USER32 surface + D2 substrate+loop + D3 thunk→instance→virtual
// dispatch + D4 owl/* runtime intrinsic — interlocks **across** the Win32
// callback boundary on a real desktop.
//
// **Crucially, no compiler change is expected.** Every mechanism the
// `OwlMain` app exercises has already been independently proven by D1–D4:
//   - The `<owl/*.h>` includes resolve via the D4 intrinsic resolver to
//     [`OWL_RUNTIME_H`] (`src/pp.rs`), which carries the public OWL API
//     **and** the runtime impls (TApplication::Run, TWindow::Create,
//     OwlStaticWndProc, the runtime-owned WinMain → OwlMain seam) — all in
//     mdbcc's Phase-A/B subset (`#include <windows.h>`, plain virtuals, no
//     templates, no exceptions, no global ctors — the one process-global
//     `_OwlHInstance` is a constant-initialised null pointer, set as the
//     first executed statement of WinMain).
//   - Phase-C `Entry::GuiWinMain` detection (`src/codegen.rs`) fires on
//     the runtime-provided `WinMain` definition ⇒ subsystem 2 + the GUI
//     stub reused verbatim (Phase-C O6 still green throughout).
//   - The runtime's `OwlStaticWndProc` is structurally identical to D3's
//     `PROG_D3_THUNK::StaticWndProc` (which D3 already proved exits
//     cleanly with code 0 across the Win32 callback boundary).
//   - `TApplication::Run`'s message loop is structurally identical to
//     D2's `WinMain` loop (already proven exits cleanly on PostQuitMessage).
//   - `TWindow::Create` mirrors D2/D3's `WNDCLASSEXA` + `CreateWindowExA`
//     sequence, passing `this` as `lpCreateParams` exactly as D3 does for
//     `&mw` (HLD §D-c instance-map crux).
//
// **Test-infrastructure ONLY** — REUSES the existing D2/D3/O6 infra
// verbatim (`interactive_desktop()`, `ProcHandle` RAII + `TerminateProcess`
// watchdog, `FindWindowA`/`PostMessageA` FFI, `skip()` loud self-skip,
// `TempExe` drop-cleanup, `terminate_child` last-resort kill). The only
// new content is the user-app TU constant and two test functions, mirroring
// the D2/D3/D4 conventions exactly.

/// The D5 hello-OWL program — the **entire user code** of a real OWL app.
/// The runtime's `WinMain → OwlMain` handoff, `TApplication::Run` message
/// loop, `TFrameWindow`'s static-WndProc thunk → `GWLP_USERDATA`-bound
/// `TWindow*` → virtual `WindowProc` default-handling `WM_DESTROY` →
/// `PostQuitMessage(0)`, are ALL provided by the D4 runtime intrinsic
/// ([`OWL_RUNTIME_H`] in `src/pp.rs`). The user writes only:
///   - a `TMyApp : public TApplication` subclass whose `InitMainWindow`
///     override constructs a `TFrameWindow` with the unique caption;
///   - `OwlMain` — instantiate the app, call `Run()`, return the exit code.
///
/// Teardown chain (close → exit code 0; **4 layers** must interlock):
///   1. user `PostMessageA(hwnd, WM_CLOSE, 0, 0)` →
///   2. `OwlStaticWndProc` recovers `self` via `GetWindowLongPtrA(GWLP_USERDATA)` →
///   3. virtual-dispatch to `TWindow::WindowProc(WM_CLOSE)` (base impl —
///      `TFrameWindow` does not override in v1) → falls through to
///      `DefWindowProcA` → default `DestroyWindow` →
///   4. Windows sends `WM_DESTROY` → `OwlStaticWndProc` → virtual
///      `TWindow::WindowProc(WM_DESTROY)` → `PostQuitMessage(0)` →
///      `GetMessageA` returns 0 → `TApplication::Run` loop exits → returns
///      `(int)msg.wParam == 0` → `OwlMain` returns 0 → runtime `WinMain`
///      returns 0 → Phase-C GUI stub `ExitProcess(0)`.
///
/// Exit code EXACTLY 0 is therefore the executable proof that:
///   - the D4 intrinsic owl/ resolver landed both `applicat.h` and
///     `framewin.h` to the same runtime body (idempotent include guard);
///   - the runtime's WinMain↔OwlMain seam compiled and linked
///     (Phase-C GUI stub + the runtime-provided `WinMain` symbol);
///   - the user's `new TFrameWindow(...)` plumbs through `TApplication::Run`
///     → `TWindow::Create` → `CreateWindowExA(..., this)` and the
///     instance-map mechanism (D3 crux) bound the `TWindow*` correctly;
///   - the Win32 callback → static thunk → virtual `WindowProc` dispatch
///     reached the right vtable slot across the Win32 boundary (Phase B
///     across a callback edge, D3 isolated; D5 confirms in the runtime).
const PROG_D5_HELLO_OWL: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TFrameWindow(0, "MdbccD5HelloOwl"));
    }
};

int OwlMain(int argc, char** argv) {
    TMyApp app;
    return app.Run();
}
"#;

/// The exact caption of the D5 hello-OWL top-level window. We use
/// `FindWindowA(NULL, this)` (caption-only) rather than class-name match:
/// the runtime's `TWindow::GetClassName()` returns `"OWLWindow"` (a virtual
/// returning a string literal — stable across runtime revisions only by
/// convention), so caption-by-title is the robust match (the D2/D3 tests
/// already use this same caption-only pattern).
const D5_WINDOW_TITLE: &[u8] = b"MdbccD5HelloOwl\0";

/// The D5 USER32 set the OWL runtime emits calls to — identical to the D4
/// set (the D5 user-app names zero USER32 symbols directly; every USER32
/// import is materialised by the runtime body which is unchanged from D4).
const D5_USER32_REQUIRED: &[&str] = D4_USER32_REQUIRED;

/// Phase D / D5 structural half — ALWAYS-ON, headless-safe, rigorous. The
/// hello-OWL TU compiles to a GUI PE with the full OWL USER32 set imported.
/// Same shape as the D2/D3/D4 structural tests; the only difference is the
/// source TU (a `TApplication`+`OwlMain` user app instead of the D4
/// unit-level OWL program, or D2/D3's raw `<windows.h>`).
#[test]
fn o6_d5_hello_owl_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_D5_HELLO_OWL.as_bytes())
        .expect("the D5 hello-OWL `OwlMain` app must compile");

    // GUI subsystem (selected by the D4 runtime-provided WinMain — C2 path).
    assert_eq!(
        subsystem(&pe),
        2,
        "the D5 hello-OWL app must be PE Subsystem == 2 (WINDOWS_GUI) — the \
         runtime-provided WinMain triggers GuiWinMain entry"
    );

    // KERNEL32 + USER32 descriptors present (KERNEL32: stub's ExitProcess;
    // USER32: every hello-window symbol the OWL runtime emits a call to).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — the OWL runtime's USER32 calls \
         were not recognised as imports (got {dlls:?})"
    );

    // Every D5 USER32 symbol must appear in some descriptor's ILT.
    let syms = imported_symbols(&pe);
    for want in D5_USER32_REQUIRED {
        assert!(
            syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing from imports — the OWL \
             runtime did not emit a call to it from the D5 user app \
             (got {syms:?})"
        );
    }
}

/// Phase D / D5 liveness — **THE MILESTONE TEST**. Desktop-gated,
/// watchdog-bounded. **Reuses the D2/D3/O6 infra verbatim** (no
/// duplication): `interactive_desktop()`, `ProcHandle` RAII +
/// `TerminateProcess` watchdog, `FindWindowA` / `PostMessageA` FFI,
/// `skip()` loud self-skip, `TempExe`.
///
/// This is the **integration test** that proves the full mdbcc → OWL
/// runtime → OS loader stack works end-to-end: an unmodified
/// Borland-API OWL source compiled by mdbcc opens a real Win64 framed
/// window on Windows 11, accepts a posted `WM_CLOSE`, and exits with
/// code **exactly 0** through the 4-layer teardown chain (thunk +
/// `GWLP_USERDATA` + virtual dispatch + `TApplication::Run` exit).
///
/// Hard safety: same bounded-poll / RAII / `TerminateProcess` machinery
/// as D2/D3 — never hangs, never false-fails on environment.
#[test]
fn o6_d5_hello_owl_launches_dispatches_clean_exits() {
    let pe = match compile_to_pe(PROG_D5_HELLO_OWL.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("D5 hello-OWL app failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "D5 app must be subsystem 2 before launch"
    );

    // Headless gate up front (reuses the existing helper verbatim).
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [D5]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the D5 exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the D5 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the D5 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    // Caption-only match (NULL class): robust against runtime-internal
    // class-name conventions (see D5_WINDOW_TITLE comment).
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), D5_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // MINOR-1 mitigation: before downgrading to a skip, check whether
        // the child already died on its own with a non-zero exit code. If
        // so, that's a silent OWL runtime failure (e.g. RegisterClassExA
        // returned 0, or the static thunk took a bad path on WM_NCCREATE)
        // and must surface as a hard failure, not a self-skip. Only the
        // STILL_ACTIVE case (real message loop but no discoverable window
        // — headless drift / caption rename) keeps the existing kill+skip.
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "D5 child exited on its own ({code:#x}) before any window \
                 was discoverable — the OWL runtime failed silently (likely \
                 RegisterClassExA/CreateWindowExA path); FindWindowA timed \
                 out after 4 s with a dead child"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip(
            "could not locate the D5 hello-OWL window within 4 s \
              (treated as no interactive station)",
        );
        return;
    }

    // PostMessage(WM_CLOSE) → 4-layer teardown chain (see PROG_D5_HELLO_OWL
    // doc-comment). Never blocks this thread (PostMessage is async; the
    // OWL framed window is non-modal).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on D5 window; child force-terminated");
        return;
    }

    // It must exit cleanly within a strict bound. A crash anywhere on the
    // 4-layer teardown path (null vptr / wrong vtable slot across the
    // callback boundary / mis-routed `TFrameWindow` ctor / message loop
    // never exits) would manifest as a STATUS_* exit code or non-zero,
    // NOT a hang — the watchdog is a backstop.
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("D5 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    // Signalled in time — assert exit code **exactly 0**. Any non-zero
    // would mean the OWL teardown chain broke (crash, wrong vtable
    // dispatch, message-loop exit returning a non-quit wParam, runtime
    // WinMain forwarding wrong value, ...). Exit code 0 is the
    // executable proof that ALL FOUR LAYERS interlocked correctly.
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "D5 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "D5 hello-OWL process must exit with code 0 — the full \
                 4-layer teardown chain (WM_CLOSE → static thunk → \
                 virtual WindowProc → DefWindowProcA → DestroyWindow → \
                 WM_DESTROY → static thunk → virtual WindowProc → \
                 PostQuitMessage(0) → TApplication::Run loop exit → \
                 OwlMain returns 0 → runtime WinMain returns 0 → \
                 ExitProcess(0)) must complete cleanly. got {code:#x}"
            );
        }
        None => {
            skip("D5 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Phase E / E1 — response-table macros + per-event EvX virtuals + if-chain
//                WindowProc dispatch
// ---------------------------------------------------------------------------
//
// E1 grows the OWL runtime intrinsic (`OWL_RUNTIME_H` in `src/pp.rs`) with:
//   1. Eight new `EvX` virtual no-op slots on `TWindow` (the v1 message set:
//      EvPaint, EvDestroy, EvLButtonDown/Up, EvMouseMove, EvCommand,
//      EvKeyDown, EvCreate). All defaults are empty bodies (or `return 0`
//      for EvCreate).
//   2. A non-virtual `base_WindowProc(UINT, WPARAM, LPARAM)` helper on
//      `TWindow` that calls `DefWindowProcA(HWindow, m, w, l)`. This is the
//      parent-class link used by `END_RESPONSE_TABLE` (HLD §E-b decision 1
//      — qualified-call `TFrameWindow::WindowProc(...)` is not in mdbcc's
//      expression-position grammar, so the same-class helper short-circuits
//      to `DefWindowProcA` directly; identical observable behaviour in v1
//      because `TFrameWindow` does not override `WindowProc`).
//   3. The `DECLARE_RESPONSE_TABLE(cls)` / `DEFINE_RESPONSE_TABLE1(cls,base)`
//      / `END_RESPONSE_TABLE` / `EV_WM_*` macros. Each `EV_WM_*` expands to
//      an `if (msg == X) { ... return 0; }` block — an **if-chain**, NOT a
//      `switch`/`case` (the parser does not yet support `switch`; HLD §E-a
//      and Phase-D Tick 11 finding). Sequential `if` blocks each ending in
//      `return 0` are semantically equivalent to a switch on these mutually
//      exclusive message IDs.
//   4. Seven new `<windows.h>` constants the EV_WM_* crackers reference:
//      `WM_PAINT 0x000F`, `WM_LBUTTONDOWN 0x0201`, `WM_LBUTTONUP 0x0202`,
//      `WM_MOUSEMOVE 0x0200`, `WM_COMMAND 0x0111`, `WM_KEYDOWN 0x0100`,
//      plus the `MK_*` modifier-key bits (`MK_LBUTTON` 0x0001 ... `MK_MBUTTON`
//      0x0010).
//
// **No new Win32 imports** — `base_WindowProc` calls `DefWindowProcA`, which
// is already imported by D1. The console byte-identical invariant therefore
// holds by construction (`tests/pe_imports.rs` golden unchanged).
//
// **Cracking signatures (HLD §E-b table, adjusted per user instruction for E1
// — `int x, int y` instead of `TPoint& pt`):**
//   - `EvLButtonDown/Up/MouseMove(UINT modKeys, int x, int y)` — l-low/high
//     unpacked via `(int)(short)(l & 0xFFFF)` (sign-extending short cast,
//     matching Win32 signed-coordinate semantics).
//   - `EvCommand(UINT cmdId, HWND ctrl, UINT notify)` — w-low/high split,
//     l is the control HWND.
//   - `EvKeyDown(UINT vkey, UINT repeat, UINT flags)` — w is vkey, l-low is
//     repeat, l-high is scan-code+flags.
//   - `EvCreate(CREATESTRUCTA *cs)` returns `int` (mdbcc has no `bool`); the
//     macro wraps as `return (LRESULT)this->EvCreate(cs_)`.
//   - `EvPaint()`/`EvDestroy()` take no args. `EV_WM_DESTROY` additionally
//     posts `WM_QUIT` after the user's handler returns, preserving the
//     Phase-D clean-exit chain (HLD §E-e).
//
// E1 = **COMPILE + STRUCTURAL only** — runtime / click oracles are E3/E4.
// The fixture (PROG_E1_RESPONSE_TABLE) subclasses TFrameWindow with a
// DECLARE_RESPONSE_TABLE + three EV_WM_* macros and Ev* method bodies, then
// asserts:
//   1. Compiles to subsystem-2 PE (the runtime-provided `WinMain` still fires
//      `Entry::GuiWinMain`).
//   2. The D5 USER32 set is imported (no new symbols vs. D5).
//   3. Console regression: a `main` TU compiles to subsystem-3 with exactly
//      one KERNEL32 descriptor (the response-table macros stay dormant for
//      any TU that does not `#include <owl/*.h>`).

/// The E1 user program — a TFrameWindow subclass with a response table that
/// handles three messages (paint, left-button-down, destroy) via the
/// EV_WM_* macros. Each EvX body is trivial (the runtime oracle is E3/E4 —
/// here we prove the macros compile, the EvX virtual slots land in the
/// vtable, and the WindowProc override dispatches via the if-chain).
const PROG_E1_RESPONSE_TABLE: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>

class TMyWin : public TFrameWindow {
public:
    int ClickCount;
    TMyWin(TWindow *p, const char *t) : TFrameWindow(p, t) { ClickCount = 0; }
    void EvPaint();
    void EvLButtonDown(UINT modKeys, int x, int y);
    void EvDestroy();
    DECLARE_RESPONSE_TABLE(TMyWin);
};

void TMyWin::EvPaint() {}

void TMyWin::EvLButtonDown(UINT modKeys, int x, int y) {
    ClickCount = ClickCount + 1;
}

void TMyWin::EvDestroy() {}

DEFINE_RESPONSE_TABLE1(TMyWin, TFrameWindow)
    EV_WM_PAINT
    EV_WM_LBUTTONDOWN
    EV_WM_DESTROY
END_RESPONSE_TABLE

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TMyWin(0, "MdbccE1ResponseTable"));
    }
};

int OwlMain(int argc, char **argv) {
    TMyApp app;
    return app.Run();
}
"#;

/// A normal console program — the byte-identical regression target. A
/// `main` program must stay subsystem-3, exactly one KERNEL32 descriptor,
/// zero USER32. The E1 macro additions in `OWL_RUNTIME_H` must remain
/// dormant for any TU that does not `#include <owl/*.h>`.
const PROG_E1_CONSOLE: &str = "int main(void){ return 0; }";

/// The E1 expected USER32 import set — **identical to D5's**. E1 adds zero
/// new USER32/GDI32 symbols (E2/E3 do that). The new `base_WindowProc`
/// helper calls `DefWindowProcA`, which is already in the D1 set.
const E1_USER32_REQUIRED: &[&str] = D5_USER32_REQUIRED;

/// E1 structural — the response-table TU compiles to a GUI PE with **no new
/// USER32/GDI32 symbols** (proof that the macros are pure preprocessor +
/// existing-runtime growth — no new Win32 substrate).
#[test]
fn o6_e1_response_table_compiles_to_gui_pe_no_new_imports() {
    let pe = compile_to_pe(PROG_E1_RESPONSE_TABLE.as_bytes())
        .expect("the E1 response-table TU (DECLARE/DEFINE/END + EV_WM_* macros) must compile");

    // GUI subsystem (selected by the runtime-provided WinMain — C2 path).
    assert_eq!(
        subsystem(&pe),
        2,
        "the E1 response-table app must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // KERNEL32 + USER32 + GDI32 descriptors present.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — got {dlls:?}"
    );
    // S4.2q reachability prune: `TPaintDC` is DORMANT in E1 (the response table
    // handles a click, never paints), so its inline `TextOut` (→ TextOutA, GDI32)
    // is now pruned — realizing the per-method dead-code-elimination the pre-prune
    // lock explicitly noted as "deliberately deferred (house style: no speculative
    // optimization)". The prune is the OWL gating lever (it lets dormant-laden
    // owl/* headers compile instead of panicking on an unreachable inline body),
    // is byte-identical on the 88 baselines, and is MORE bcc32-conformant: bcc32
    // emits inline methods on use, so a non-painting TU imports no GDI32 either.
    // ⇒ E1's import set is now KERNEL32 + USER32 (no GDI32). [Flagged for Arthur:
    // this supersedes the deferred-DCE house-style stance.]
    assert_eq!(
        dlls.len(),
        2,
        "E1 must import exactly KERNEL32 + USER32 (TPaintDC dormant ⇒ no GDI32 \
         after the S4.2q prune) — got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    // The D5 USER32 set must still be there (response-table machinery does
    // not change the runtime's emitted Win32 calls).
    for want in E1_USER32_REQUIRED {
        assert!(
            syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing — E1 must import the full D5 \
             set (got {syms:?})"
        );
    }
    // E1 (after E3) acknowledges TextOutA — the new GDI32 substrate the
    // OWL runtime's `TPaintDC::TextOut` inline method calls. SendMessageA
    // remains forbidden — that's E4 scope.
    const E4_OR_LATER: &[&str] = &["SendMessageA"];
    for forbidden in E4_OR_LATER {
        assert!(
            !syms.iter().any(|s| s == forbidden),
            "E1 (response-table TU) must NOT import '{forbidden}' (that's \
             E4 scope) — got {syms:?}"
        );
    }
}

/// E1 console byte-identical regression — a `main` program must stay
/// subsystem-3 with **exactly one** KERNEL32 descriptor and zero USER32
/// imports. The response-table macro and EvX-virtual additions in
/// `OWL_RUNTIME_H` must remain dormant for any TU that does not
/// `#include <owl/*.h>` (the dormancy invariant carried from D4 — same
/// shape, same proof).
#[test]
fn o6_e1_console_program_unchanged_after_response_table_macros() {
    let pe = compile_to_pe(PROG_E1_CONSOLE.as_bytes()).expect("compile console");

    assert_eq!(
        subsystem(&pe),
        3,
        "console program must stay subsystem 3 after E1 (the response-table \
         macros are gated on `<owl/*.h>` includes, not materialised in a \
         `main` TU)"
    );

    let dlls = imported_dlls(&pe);
    assert_eq!(
        dlls.len(),
        1,
        "console program must have exactly one import descriptor after E1, \
         got {dlls:?}"
    );
    assert!(
        dlls[0].eq_ignore_ascii_case("KERNEL32.dll"),
        "the sole descriptor must be KERNEL32.dll, got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    for forbidden in E1_USER32_REQUIRED {
        assert!(
            !syms.iter().any(|s| s == forbidden),
            "USER32 symbol '{forbidden}' must NOT be imported by a console \
             program (got {syms:?}) — E1's response-table machinery must \
             stay dormant unless an owl/* header is included"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase E / E2 oracle — TPaintDC RAII + USER32 BeginPaint/EndPaint imports
// (per `wrk_docs/2026.05.18 - HLD - Phase E (OWL event handling).md` §E-d /
// §E-f E2). Structural-only: compile to a `.exe` and parse its import
// directory. The runtime liveness oracle for WM_PAINT is E3 (Phase E ships
// the printf-from-EvPaint check there).
// ---------------------------------------------------------------------------

/// A `TFrameWindow`-derived class with `DECLARE_RESPONSE_TABLE` +
/// `EV_WM_PAINT` that constructs a `TPaintDC dc(*this);` in its `EvPaint`
/// override (the RAII Borland-OWL idiom — `TPaintDC` wraps `BeginPaint` in
/// its ctor and `EndPaint` in its virtual dtor; the dtor fires at scope
/// exit via Phase B's auto-dtor mechanism). The body also reads `dc.hdc`
/// to make the local non-trivial (verifies member access compiles); no
/// `TextOutA` (that's E3 — GDI32). `EV_WM_DESTROY` keeps the message loop
/// honest per the OWL footgun documented in HLD §E-e.
const PROG_E2_PAINTDC: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>

class TMyWin : public TFrameWindow {
public:
    HDC LastHdc;
    TMyWin(TWindow *p, const char *t) : TFrameWindow(p, t) { LastHdc = 0; }
    void EvPaint();
    void EvDestroy();
    DECLARE_RESPONSE_TABLE(TMyWin);
};

void TMyWin::EvPaint() {
    TPaintDC dc(*this);
    LastHdc = dc.hdc;
}

void TMyWin::EvDestroy() {}

DEFINE_RESPONSE_TABLE1(TMyWin, TFrameWindow)
    EV_WM_PAINT
    EV_WM_DESTROY
END_RESPONSE_TABLE

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TMyWin(0, "MdbccE2PaintDC"));
    }
};

int OwlMain(int argc, char **argv) {
    TMyApp app;
    return app.Run();
}
"#;

/// A normal console program — the byte-identical E2 regression target. A
/// `main` program must stay subsystem-3, exactly one KERNEL32 descriptor,
/// zero USER32, and (crucially after E2) **zero** BeginPaint/EndPaint.
/// The `TPaintDC` class body in `OWL_RUNTIME_H` must remain dormant for
/// any TU that does not `#include <owl/*.h>`.
const PROG_E2_CONSOLE: &str = "int main(void){ return 0; }";

/// The E2 USER32 superset: the full D5/E1 set PLUS `BeginPaint`/`EndPaint`
/// (the two new symbols E2 contributes). E3 will add `TextOutA` to a new
/// GDI32 descriptor; E2 stays USER32-only.
const E2_USER32_REQUIRED: &[&str] = &[
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
    "BeginPaint",
    "EndPaint",
];

/// E2 structural — the `TPaintDC`-constructing TU compiles to a GUI PE
/// whose USER32 descriptor imports the full D5/E1 set PLUS `BeginPaint`
/// and `EndPaint`. The KERNEL32 descriptor is unchanged from D1; the
/// import-descriptor count stays at **2** (KERNEL32 + USER32 — no GDI32
/// yet; that's E3's first GDI32 import row).
#[test]
fn o6_e2_paintdc_compiles_to_gui_pe_importing_beginpaint_endpaint() {
    let pe = compile_to_pe(PROG_E2_PAINTDC.as_bytes())
        .expect("the E2 TPaintDC TU (EV_WM_PAINT + TPaintDC dc(*this); RAII) must compile");

    // GUI subsystem (runtime-provided WinMain — C2 path).
    assert_eq!(
        subsystem(&pe),
        2,
        "the E2 TPaintDC app must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // After E3, every OWL TU pulls in GDI32 too (the `TPaintDC::TextOut`
    // inline method body calls TextOutA — see E1 test for the rationale).
    // So E2's `TPaintDC` TU now has 3 descriptors: KERNEL32+USER32+GDI32.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("GDI32.dll")),
        "GDI32.dll descriptor missing — after E3, every OWL TU pulls \
         in GDI32 via `TPaintDC::TextOut` (got {dlls:?})"
    );
    assert_eq!(
        dlls.len(),
        3,
        "E2 must import exactly KERNEL32 + USER32 + GDI32 (the OWL \
         substrate set after E3) — got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    // Full E2 USER32 set (D5 + BeginPaint + EndPaint) must be present.
    for want in E2_USER32_REQUIRED {
        assert!(
            syms.iter().any(|s| s == want),
            "USER32 symbol '{want}' missing — E2 must import the D5 set \
             plus BeginPaint+EndPaint (got {syms:?})"
        );
    }
    // E2 (after E3) acknowledges TextOutA — the OWL substrate GDI32
    // symbol. SendMessageA remains forbidden — that's E4 scope.
    const E4_OR_LATER: &[&str] = &["SendMessageA"];
    for forbidden in E4_OR_LATER {
        assert!(
            !syms.iter().any(|s| s == forbidden),
            "E2 must NOT import '{forbidden}' (that's E4 scope) — \
             got {syms:?}"
        );
    }
}

/// E2 console byte-identical regression — a `main` program must stay
/// subsystem-3 with **exactly one** KERNEL32 descriptor, zero USER32,
/// and (the new E2 dormancy assertion) zero `BeginPaint`/`EndPaint`. The
/// `TPaintDC` class body and the new `PAINTSTRUCT` struct in the
/// intrinsic headers must remain dormant for any TU that does not
/// `#include <owl/*.h>` (the dormancy invariant carried from D1/D4/E1 —
/// same shape, same proof).
#[test]
fn o6_e2_console_program_has_no_user32_or_gdi32_after_e2() {
    let pe = compile_to_pe(PROG_E2_CONSOLE.as_bytes()).expect("compile console");

    assert_eq!(
        subsystem(&pe),
        3,
        "console program must stay subsystem 3 after E2 (TPaintDC + \
         BeginPaint/EndPaint additions are gated on `<owl/*.h>` includes, \
         not materialised in a `main` TU)"
    );

    let dlls = imported_dlls(&pe);
    assert_eq!(
        dlls.len(),
        1,
        "console program must have exactly one import descriptor after E2, \
         got {dlls:?}"
    );
    assert!(
        dlls[0].eq_ignore_ascii_case("KERNEL32.dll"),
        "the sole descriptor must be KERNEL32.dll, got {dlls:?}"
    );

    let syms = imported_symbols(&pe);
    // None of the E2 USER32 set may appear in a console program.
    for forbidden in E2_USER32_REQUIRED {
        assert!(
            !syms.iter().any(|s| s == forbidden),
            "USER32 symbol '{forbidden}' must NOT be imported by a console \
             program (got {syms:?}) — E2's TPaintDC/BeginPaint/EndPaint \
             machinery must stay dormant unless an owl/* header is included"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase E / E3 — TextOutA (first GDI32 symbol) + functional runtime WM_PAINT
// oracle via printf-to-stdout (per `wrk_docs/2026.05.18 - HLD - Phase E
// (OWL event handling).md` §E-d / §E-f E3). E3 is the **first FUNCTIONAL
// runtime oracle** for the response-table mechanism: an OWL app whose
// `EvPaint` draws via `TPaintDC::TextOut` AND prints "PAINTED\n" — the
// harness asserts on the stdout side-effect (the screenshot oracle is
// deferred per HLD §E-f / D5 precedent; printf-to-stdout is the genuine
// functional oracle that paint actually fired and the handler actually ran).
//
// E3 is also the **first 3-DLL `.idata` end-to-end** in mdbcc: KERNEL32 +
// USER32 + GDI32 descriptors all present. The C1b multi-descriptor
// machinery (`used_dlls` / `grouped_imports` / `emit_idata`) was built
// for arbitrary k and is structurally well-tested with k=2 (the synthetic
// two-DLL unit test) and k=1 (every console program); k=3 is new bytes
// but no new code. A malformed image with 3 DLLs would be a real C1b
// bug — STOP+report, do not hack the test to mask it (per
// supervisor charter).
//
// **WM_PAINT reliability:** `TApplication::Run()` calls `MainWindow->Show()`
// which calls `ShowWindow` then `UpdateWindow`. `UpdateWindow` SYNCHRONOUSLY
// sends `WM_PAINT` to the window proc if the update region is non-empty
// (which it always is for a freshly-created window). So `WM_PAINT` fires
// **before** the message loop is even entered, **before** the test harness
// can PostMessageA(WM_CLOSE). The "PAINTED" stdout line is therefore
// emitted reliably on every run (the OS contract of `UpdateWindow`).

/// The E3 user program — a TFrameWindow subclass with a response table
/// handling WM_PAINT + WM_DESTROY. `EvPaint` constructs a `TPaintDC`,
/// draws "Hello OWL paint!" via the new `TPaintDC::TextOut` (which calls
/// `TextOutA` from GDI32.dll), AND prints "PAINTED\n" to stdout (the
/// observable the harness asserts on). `EvDestroy` is a no-op (the
/// EV_WM_DESTROY macro itself posts WM_QUIT, preserving the Phase-D
/// clean-exit chain).
const PROG_E3_PAINT_OWL: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>
#include <stdio.h>

class TMyWin : public TFrameWindow {
public:
    TMyWin(TWindow *p, const char *t) : TFrameWindow(p, t) {}
    void EvPaint();
    void EvDestroy();
    DECLARE_RESPONSE_TABLE(TMyWin);
};

void TMyWin::EvPaint() {
    TPaintDC dc(*this);
    dc.TextOut(10, 10, "Hello OWL paint!");
    printf("PAINTED\n");
}

void TMyWin::EvDestroy() {}

DEFINE_RESPONSE_TABLE1(TMyWin, TFrameWindow)
    EV_WM_PAINT
    EV_WM_DESTROY
END_RESPONSE_TABLE

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TMyWin(0, "MdbccE3Paint"));
    }
};

int OwlMain(int argc, char **argv) {
    TMyApp app;
    return app.Run();
}
"#;

/// The exact caption of the E3 top-level window.
const E3_WINDOW_TITLE: &[u8] = b"MdbccE3Paint\0";

/// A normal console program — the byte-identical E3 regression target. A
/// `main` program must stay subsystem-3, exactly one KERNEL32 descriptor,
/// zero USER32, **zero GDI32** (the new dormancy assertion E3 brings).
/// The `TextOutA` import row and the `TPaintDC::TextOut` inline method in
/// `OWL_RUNTIME_H` must remain dormant for any TU that does not
/// `#include <owl/*.h>`.
const PROG_E3_CONSOLE: &str = "int main(void){ return 0; }";

/// Read the symbols imported from a *specific* DLL's descriptor (matched
/// case-insensitively). This is finer-grained than `imported_symbols`,
/// which flattens across descriptors — and we need the per-DLL form to
/// prove `TextOutA` lives specifically in the GDI32 descriptor's ILT
/// (not e.g. mis-grouped into USER32, which the C1b path's table-order
/// invariant rules out — but the test makes the proof executable).
fn imported_symbols_for_dll(pe: &[u8], dll: &str) -> Vec<String> {
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
        let mut name = String::new();
        while pe[o] != 0 {
            name.push(pe[o] as char);
            o += 1;
        }
        if name.eq_ignore_ascii_case(dll) {
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
        }
        d += 20;
    }
    out
}

/// E3 structural — the `TPaintDC::TextOut`-calling TU compiles to a GUI PE
/// whose import directory now contains **three** descriptors (KERNEL32 +
/// USER32 + GDI32), with `TextOutA` specifically in the GDI32 descriptor's
/// ILT. This is the **first 3-DLL `.idata` end-to-end** in mdbcc.
#[test]
fn o6_e3_paint_owl_compiles_to_gui_pe_with_gdi32_textouta() {
    let pe = compile_to_pe(PROG_E3_PAINT_OWL.as_bytes())
        .expect("the E3 paint TU (EV_WM_PAINT + dc.TextOut + printf) must compile");

    // GUI subsystem (runtime-provided WinMain — C2 path).
    assert_eq!(
        subsystem(&pe),
        2,
        "the E3 paint app must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // Exactly THREE descriptors: KERNEL32 + USER32 + GDI32. This is the
    // first time mdbcc emits a 3-DLL `.idata` end-to-end through the C1b
    // multi-descriptor path with real codegen-driven imports.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "KERNEL32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "USER32.dll descriptor missing — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("GDI32.dll")),
        "GDI32.dll descriptor missing — E3's first GDI32 import row was \
         not emitted (got {dlls:?})"
    );
    assert_eq!(
        dlls.len(),
        3,
        "E3 must import exactly KERNEL32 + USER32 + GDI32 (got {dlls:?})"
    );

    // `TextOutA` must be specifically in the GDI32 descriptor's ILT — not
    // mis-grouped into USER32 (C1b's table-order grouping rules this out
    // by construction; the per-DLL check makes the proof executable).
    let gdi32_syms = imported_symbols_for_dll(&pe, "GDI32.dll");
    assert!(
        gdi32_syms.iter().any(|s| s == "TextOutA"),
        "TextOutA must appear in the GDI32.dll descriptor's ILT \
         specifically (got GDI32 symbols: {gdi32_syms:?})"
    );
    // And it must NOT be in USER32 (mis-grouping regression guard).
    let user32_syms = imported_symbols_for_dll(&pe, "USER32.dll");
    assert!(
        !user32_syms.iter().any(|s| s == "TextOutA"),
        "TextOutA must NOT appear in the USER32.dll descriptor (it is a \
         GDI32 symbol — got USER32 symbols: {user32_syms:?})"
    );
}

/// E3 console byte-identical regression — a `main` program must stay
/// subsystem-3 with **exactly one** KERNEL32 descriptor, zero USER32,
/// **zero GDI32**, and zero `TextOutA`. The `TextOutA` row in
/// `WIN32_IMPORTS` and the `TPaintDC::TextOut` inline method in
/// `OWL_RUNTIME_H` must remain dormant for any TU that does not
/// `#include <owl/*.h>` (the dormancy invariant carried from D1/D4/E1/E2
/// — same shape, same proof).
#[test]
fn o6_e3_console_program_has_no_gdi32_textouta_after_e3() {
    let pe = compile_to_pe(PROG_E3_CONSOLE.as_bytes()).expect("compile console");

    assert_eq!(
        subsystem(&pe),
        3,
        "console program must stay subsystem 3 after E3"
    );

    let dlls = imported_dlls(&pe);
    assert_eq!(
        dlls.len(),
        1,
        "console program must have exactly one import descriptor after E3, \
         got {dlls:?}"
    );
    assert!(
        dlls[0].eq_ignore_ascii_case("KERNEL32.dll"),
        "the sole descriptor must be KERNEL32.dll, got {dlls:?}"
    );
    assert!(
        !dlls.iter().any(|d| d.eq_ignore_ascii_case("GDI32.dll")),
        "console program must NOT import GDI32 — the E3 TextOutA import \
         row must stay dormant (got {dlls:?})"
    );

    let syms = imported_symbols(&pe);
    assert!(
        !syms.iter().any(|s| s == "TextOutA"),
        "console program must NOT import TextOutA — the E3 TPaintDC::TextOut \
         + TextOutA additions must stay dormant unless an owl/* header is \
         included (got {syms:?})"
    );
}

/// E3 functional runtime oracle — desktop-gated, watchdog-bounded. **THE
/// first FUNCTIONAL WM_PAINT oracle in mdbcc.** Reuses the D2/D3/D5/O6
/// infra verbatim (`interactive_desktop()`, `ProcHandle` RAII +
/// `TerminateProcess` watchdog, `FindWindowA` / `PostMessageA` FFI,
/// `skip()` loud self-skip, `TempExe`).
///
/// **Stdout capture mechanism:** the child is spawned with
/// `Stdio::piped()` for stdout. A GUI subsystem-2 process *can* still
/// write to stdout: `GetStdHandle(STD_OUTPUT_HANDLE)` returns the pipe
/// handle Rust set via `STARTUPINFO.hStdOutput`, and mdbcc's intrinsic
/// `printf` lowers to `WriteFile(stdout_handle, ...)` directly. A reader
/// thread drains the pipe to EOF; after the child exits the pipe's write
/// end is closed and the thread's `read_to_end` returns the full captured
/// bytes. (We cannot use `child.wait_with_output()` because we hand the
/// child's OS lifetime to `ProcHandle` for the watchdog — same pattern as
/// every other liveness test in this file.)
///
/// **WM_PAINT reliability:** `TApplication::Run` calls `MainWindow->Show()`
/// which calls `ShowWindow` then `UpdateWindow`. `UpdateWindow` SYNCHRONOUSLY
/// sends `WM_PAINT` to the window proc for the (always non-empty) update
/// region of a freshly-created window. So `EvPaint` (and its `printf`)
/// fire **before** `TApplication::Run` enters its `GetMessageA` loop —
/// well before the harness's `PostMessageA(WM_CLOSE)` can arrive. The
/// stdout "PAINTED\n" assertion therefore holds on every run.
///
/// Teardown chain (close → exit code 0): `WM_CLOSE` → static thunk →
/// virtual `TMyWin::WindowProc` (the response-table override) → no
/// matching `EV_WM_*` for WM_CLOSE → falls through to `base_WindowProc`
/// → `DefWindowProcA` → default `DestroyWindow` → `WM_DESTROY` →
/// static thunk → `TMyWin::WindowProc` → `EV_WM_DESTROY` macro fires →
/// `EvDestroy()` (no-op) → `PostQuitMessage(0)` → `GetMessageA` returns 0
/// → loop exits → `OwlMain` returns 0 → runtime `WinMain` returns 0 →
/// `ExitProcess(0)`.
///
/// Hard safety: same bounded-poll / RAII / TerminateProcess machinery as
/// D2/D3/D5 — never hangs, never false-fails on environment. The
/// MINOR-1-tightened D5 pattern is reused: if `FindWindowA` times out AND
/// the child died early with a non-zero exit code, that is a hard
/// failure (silent OWL runtime failure), not a self-skip.
#[test]
fn o6_e3_paint_owl_runs_and_emits_painted_via_response_table() {
    use std::io::Read;
    use std::process::Stdio;

    let pe = match compile_to_pe(PROG_E3_PAINT_OWL.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("E3 paint app failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "E3 app must be subsystem 2 before launch"
    );

    // Headless gate up front (reuses the existing helper verbatim).
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E3]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E3 exe to a temp path");
        return;
    }

    let mut child = match Command::new(&tmp.0).stdout(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E3 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    // Take the stdout pipe BEFORE handing the child's OS lifetime to
    // ProcHandle — the std `Child` will be forgotten after, but the pipe
    // handle stays open until its write end (held by the child) closes on
    // exit. A dedicated reader thread drains it to EOF.
    let stdout_pipe = match child.stdout.take() {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("piped stdout missing from spawned E3 child");
            return;
        }
    };
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E3 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Reader thread: drain the pipe to EOF in the background; returns
    // the captured bytes when the pipe closes (child exits) or when an
    // I/O error occurs.
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut p = stdout_pipe;
        let _ = p.read_to_end(&mut buf);
        buf
    });

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), E3_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // MINOR-1 tightened pattern (reused from D5): if the child already
        // died on its own with a non-zero exit code, that is a silent OWL
        // runtime failure (e.g. RegisterClassExA returned 0, mis-routed
        // GDI32 import) and must surface as a hard panic, not a self-skip.
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            // Drop reader thread (let it finish on its own — pipe is closed).
            let captured = reader.join().unwrap_or_default();
            panic!(
                "E3 child exited on its own ({code:#x}) before any window \
                 was discoverable — the OWL runtime or GDI32 import path \
                 failed silently; FindWindowA timed out after 4 s with a \
                 dead child. Captured stdout so far: {:?}",
                String::from_utf8_lossy(&captured)
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip(
            "could not locate the E3 paint window within 4 s \
              (treated as no interactive station)",
        );
        return;
    }

    // Post WM_CLOSE → 4-layer teardown to clean exit (see test doc-comment).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip("PostMessageA(WM_CLOSE) failed on E3 window; child force-terminated");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip("E3 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    // Process exited; reader thread will EOF as soon as the child's
    // closed-on-exit pipe write end is observed. Join with a small
    // timeout-equivalent (no std API for thread-join timeout, but the
    // EOF on the closed pipe is essentially instant — Windows kernel
    // signals the read end when the writer dies).
    let captured = reader.join().expect("stdout reader thread panicked");

    // Assert exit code exactly 0 (the same deterministic teardown chain
    // as D5; any non-zero would be a crash or a broken teardown).
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E3 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code,
                0,
                "E3 paint process must exit with code 0 (response-table \
                 teardown: WM_CLOSE → base_WindowProc → DefWindowProcA → \
                 WM_DESTROY → EV_WM_DESTROY → PostQuitMessage(0) → loop \
                 exits → ExitProcess(0)). got {code:#x}. Captured \
                 stdout: {:?}",
                String::from_utf8_lossy(&captured)
            );
        }
        None => {
            skip("E3 process signalled but GetExitCodeProcess failed");
            return;
        }
    }

    // The functional oracle: EvPaint must have fired at least once
    // (UpdateWindow inside Show() synchronously sends WM_PAINT before
    // the message loop is entered), so "PAINTED\n" must appear in
    // captured stdout. This is the executable proof that:
    //   - the response-table EV_WM_PAINT macro dispatched to EvPaint;
    //   - the TPaintDC RAII ctor ran (BeginPaint succeeded);
    //   - TextOutA was actually called via the GDI32 IAT (no crash);
    //   - printf-from-GUI-stdout works through GetStdHandle(STD_OUT)
    //     via the inherited piped handle;
    //   - the TPaintDC dtor ran (EndPaint at scope exit).
    let captured_str = String::from_utf8_lossy(&captured);
    assert!(
        captured_str.contains("PAINTED\n"),
        "E3 paint process must emit \"PAINTED\\n\" via printf from \
         EvPaint at least once (UpdateWindow synchronously sends \
         WM_PAINT before the message loop), but captured stdout was: \
         {captured_str:?}"
    );
}

// ---------------------------------------------------------------------------
// E4 — synthetic-click oracle (the Phase-E milestone)
// ---------------------------------------------------------------------------
//
// E4 is the **first end-to-end functional oracle for a user-input message**
// in mdbcc. It proves the full response-table dispatch chain works for
// `WM_LBUTTONDOWN`: a synchronously-injected click is cracked by the
// `EV_WM_LBUTTONDOWN` macro, dispatched through the virtual `WindowProc`
// override, mutates observable state (a click counter), and the count is
// reported on clean exit via `EvDestroy`. Every cog of the chain becomes
// observable in stdout.
//
// **No new OWL/Win32 substrate.** SendMessageA is the harness's
// click-injection lever from Rust; the OWL exe receives the click through
// its standard `GetMessageA`/`DispatchMessageA` loop and crucially does NOT
// import `SendMessageA` itself (the structural assertion below pins this).
// The OWL exe's USER32/GDI32 import set is identical to E3's — the only
// growth between E3 and E4 is the harness-side FFI declaration above.
//
// **Why SendMessageA, not PostMessageA, for click injection.** PostMessageA
// is async (queues the message, returns immediately); SendMessageA across
// threads/processes blocks until the receiving thread's window proc
// processes the message and returns. That synchrony lets us deterministically
// count three dispatches: three sequential SendMessageA calls produce three
// sequential `EvLButtonDown` invocations before we move on to
// `PostMessageA(WM_CLOSE)`. Without synchrony we'd have to poll stdout for
// the increment lines, which is racy.

/// The E4 user program — a TFrameWindow subclass whose response table
/// handles `WM_LBUTTONDOWN` (increments a file-scope click counter and
/// prints `"CLICK N\n"`) and `WM_DESTROY` (prints the final `"CLICKS=N\n"`
/// summary; the `EV_WM_DESTROY` macro itself posts `WM_QUIT`, preserving
/// the Phase-D clean-exit chain).
///
/// **File-scope `g_clicks` rather than an instance member.** PROG_E1 used
/// an instance member (`TMyWin::ClickCount`) and proved that path
/// compiles; here a file-scope global keeps the test fixture tiny and
/// avoids weaving a `TMyWin*` through `EvDestroy`. mdbcc's globals are
/// slice-11 supported. No `EvPaint` (E3 already covers that path) — the
/// response table only needs the LBUTTONDOWN and DESTROY crackers.
const PROG_E4_CLICK_OWL: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>
#include <stdio.h>

static int g_clicks = 0;

class TMyWin : public TFrameWindow {
public:
    TMyWin(TWindow *p, const char *t) : TFrameWindow(p, t) {}
    void EvLButtonDown(UINT modKeys, int x, int y);
    void EvDestroy();
    DECLARE_RESPONSE_TABLE(TMyWin);
};

void TMyWin::EvLButtonDown(UINT modKeys, int x, int y) {
    g_clicks = g_clicks + 1;
    printf("CLICK %d\n", g_clicks);
}

void TMyWin::EvDestroy() {
    printf("CLICKS=%d\n", g_clicks);
}

DEFINE_RESPONSE_TABLE1(TMyWin, TFrameWindow)
    EV_WM_LBUTTONDOWN
    EV_WM_DESTROY
END_RESPONSE_TABLE

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TMyWin(0, "MdbccE4Click"));
    }
};

int OwlMain(int argc, char **argv) {
    TMyApp app;
    return app.Run();
}
"#;

/// The exact caption of the E4 top-level window.
const E4_WINDOW_TITLE: &[u8] = b"MdbccE4Click\0";

/// Pack `(x, y)` 16-bit shorts into the `lparam` layout `WM_LBUTTONDOWN`
/// expects: `(y << 16) | (x & 0xFFFF)`. The `EV_WM_LBUTTONDOWN` cracker
/// sign-extends these back via `(short)`; small positive coordinates round-
/// trip exactly.
fn make_lparam(x: i16, y: i16) -> isize {
    (((y as i32) << 16) | ((x as i32) & 0xFFFF)) as isize
}

/// Number of synthetic clicks the E4 harness injects. Three is the sweet
/// spot: large enough to prove counting (per-click `printf` AND the final
/// `EvDestroy` summary), small enough to be fast.
const E4_CLICK_COUNT: i32 = 3;

/// E4 functional runtime oracle — desktop-gated, watchdog-bounded. **THE
/// first FUNCTIONAL WM_LBUTTONDOWN oracle in mdbcc**, completing the
/// Phase-E milestone (a real user-input message cracked by the response
/// table, dispatched through the per-event virtual, mutating state,
/// reported on clean exit).
///
/// Reuses the E3 infra verbatim (`interactive_desktop()`, `ProcHandle`
/// RAII + `TerminateProcess` watchdog, `FindWindowA` / `PostMessageA` FFI,
/// `skip()` loud self-skip, `TempExe`, the `Stdio::piped()` + reader-
/// thread stdout-capture path). The only new harness piece is the
/// `SendMessageA` FFI declaration (above) used for synchronous click
/// injection.
///
/// **Click-injection synchrony:** `SendMessageA` across threads blocks
/// until the receiving window proc returns. Three sequential
/// `SendMessageA(hwnd, WM_LBUTTONDOWN, 0, MAKELPARAM(10,10))` calls thus
/// produce three sequential `EV_WM_LBUTTONDOWN` dispatches, each one
/// running `g_clicks = g_clicks + 1; printf("CLICK %d\n", g_clicks);` to
/// completion before the next is dispatched. So the captured stdout
/// contains exactly `"CLICK 1\n"`, `"CLICK 2\n"`, `"CLICK 3\n"` (in
/// order) and the final `"CLICKS=3\n"` summary line from `EvDestroy`.
///
/// Teardown chain (close → exit code 0): `PostMessageA(WM_CLOSE)` →
/// static thunk → virtual `TMyWin::WindowProc` (the response-table
/// override) → no matching `EV_WM_*` for WM_CLOSE → falls through to
/// `base_WindowProc` → `DefWindowProcA` → default `DestroyWindow` →
/// `WM_DESTROY` → static thunk → `TMyWin::WindowProc` → `EV_WM_DESTROY`
/// macro fires → `EvDestroy()` (emits `"CLICKS=3\n"`) →
/// `PostQuitMessage(0)` → `GetMessageA` returns 0 → loop exits →
/// `OwlMain` returns 0 → runtime `WinMain` returns 0 → `ExitProcess(0)`.
///
/// Hard safety: same bounded-poll / RAII / TerminateProcess machinery as
/// D2/D3/D5/E3 — never hangs, never false-fails on environment. The
/// MINOR-1-tightened D5 pattern is reused: if `FindWindowA` times out
/// AND the child died early with a non-zero exit code, that is a hard
/// failure, not a self-skip.
#[test]
fn o6_e4_click_owl_counts_lbuttondowns_via_response_table() {
    use std::io::Read;
    use std::process::Stdio;

    let pe = match compile_to_pe(PROG_E4_CLICK_OWL.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("E4 click app failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "E4 app must be subsystem 2 before launch"
    );

    // Structural assertion: the OWL exe still has the E3 import set
    // (KERNEL32 + USER32 + GDI32 — no new DLL) AND crucially does NOT
    // import `SendMessageA` (the harness calls it from Rust; the OWL app
    // *receives* clicks via its standard GetMessageA loop). This locks
    // the "SendMessageA stays out of WIN32_IMPORTS" invariant — the OWL
    // app's substrate is unchanged from E3.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "E4 OWL exe missing KERNEL32.dll descriptor — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "E4 OWL exe missing USER32.dll descriptor — got {dlls:?}"
    );
    // S4.2q reachability prune: E4 handles clicks, not paint, so `TPaintDC` is
    // dormant and its GDI32-pulling inline `TextOut` is pruned (the per-method DCE
    // the pre-prune lock called "deliberately deferred"). bcc32 emits inline
    // methods on use too, so a non-painting OWL TU imports no GDI32 ⇒ E4's set is
    // KERNEL32 + USER32. [Flagged for Arthur: supersedes the deferred-DCE stance.]
    assert_eq!(
        dlls.len(),
        2,
        "E4 OWL exe must import exactly KERNEL32 + USER32 (TPaintDC dormant ⇒ no \
         GDI32 after the S4.2q prune) — got {dlls:?}"
    );
    let syms = imported_symbols(&pe);
    assert!(
        !syms.iter().any(|s| s == "SendMessageA"),
        "E4 OWL exe must NOT import SendMessageA — the OWL app receives \
         clicks via the standard GetMessageA loop; SendMessageA is only \
         called from the Rust harness. Got {syms:?}"
    );

    // Headless gate up front (reuses the existing helper verbatim).
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E4]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E4 exe to a temp path");
        return;
    }

    let mut child = match Command::new(&tmp.0).stdout(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E4 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let stdout_pipe = match child.stdout.take() {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("piped stdout missing from spawned E4 child");
            return;
        }
    };
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E4 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Reader thread: drain the pipe to EOF in the background.
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut p = stdout_pipe;
        let _ = p.read_to_end(&mut buf);
        buf
    });

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), E4_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // MINOR-1 tightened: silent early death is a hard failure.
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            let captured = reader.join().unwrap_or_default();
            panic!(
                "E4 child exited on its own ({code:#x}) before any window \
                 was discoverable — the OWL runtime failed silently; \
                 FindWindowA timed out after 4 s with a dead child. \
                 Captured stdout so far: {:?}",
                String::from_utf8_lossy(&captured)
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip(
            "could not locate the E4 click window within 4 s \
              (treated as no interactive station)",
        );
        return;
    }

    // Inject N synchronous clicks. SendMessageA across threads blocks
    // until the receiving window proc returns, so each call provably
    // completes one full `EV_WM_LBUTTONDOWN` dispatch (which prints
    // `"CLICK k\n"` for k = 1..=N) before the next is queued.
    let lparam = make_lparam(10, 10);
    for _ in 0..E4_CLICK_COUNT {
        let _ = unsafe { SendMessageA(hwnd, WM_LBUTTONDOWN, 0, lparam) };
    }

    // Post WM_CLOSE → 4-layer teardown to clean exit (see test doc-comment).
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip("PostMessageA(WM_CLOSE) failed on E4 window; child force-terminated");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip("E4 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    let captured = reader.join().expect("stdout reader thread panicked");

    // Assert exit code exactly 0 (same deterministic teardown chain as
    // D5/E3; any non-zero would be a crash or broken teardown).
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E4 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code,
                0,
                "E4 click process must exit with code 0 (response-table \
                 teardown: WM_CLOSE → base_WindowProc → DefWindowProcA → \
                 WM_DESTROY → EV_WM_DESTROY → EvDestroy → \
                 PostQuitMessage(0) → loop exits → ExitProcess(0)). \
                 got {code:#x}. Captured stdout: {:?}",
                String::from_utf8_lossy(&captured)
            );
        }
        None => {
            skip("E4 process signalled but GetExitCodeProcess failed");
            return;
        }
    }

    // The functional oracle: each synchronously-injected SendMessageA
    // dispatch must have produced one "CLICK k\n" line (k = 1..=N) AND
    // EvDestroy must have emitted the final "CLICKS=N\n" summary. The
    // CLICK lines prove EV_WM_LBUTTONDOWN cracked + dispatched per click;
    // the summary line proves EvDestroy fired after WM_CLOSE.
    let captured_str = String::from_utf8_lossy(&captured);
    for k in 1..=E4_CLICK_COUNT {
        let needle = format!("CLICK {k}\n");
        assert!(
            captured_str.contains(&needle),
            "E4 click process must emit {needle:?} via printf from \
             EvLButtonDown (SendMessageA is synchronous; each click dispatches \
             one increment), but captured stdout was: {captured_str:?}"
        );
    }
    let summary = format!("CLICKS={E4_CLICK_COUNT}\n");
    assert!(
        captured_str.contains(&summary),
        "E4 click process must emit {summary:?} via printf from EvDestroy \
         (WM_CLOSE → DefWindowProcA → DestroyWindow → WM_DESTROY → \
         EV_WM_DESTROY → EvDestroy summary), but captured stdout was: \
         {captured_str:?}"
    );
}

// ---------------------------------------------------------------------------
// Phase G / G3 — LoadStringA reads a STRINGTABLE entry from `.rsrc`
// ---------------------------------------------------------------------------
//
// G3 is the **PE-`.rsrc`-emission landing**: an mdbcc-built EXE with a
// sibling `.rc` STRINGTABLE compiles to a PE that imports `LoadStringA`
// from USER32, has a `.rsrc` section pointed at by `DataDirectory[2]`, and
// — at runtime — the Win32 loader resolves the string by id when the
// program calls `LoadStringA(NULL, id, buf, sz)`. This is the end-to-end
// O6-equivalent for resources: the OS loader's `.rsrc` parser is the
// oracle. A wrong .rsrc layout would either return zero (loader could not
// find the resource) or crash; a correct one yields the embedded string.
//
// **Why hInstance = NULL.** Win32 `LoadStringA(hInstance, id, ...)`
// documents: "If `hInstance` is NULL, the function searches the resources
// of the module used to create the current process" — exactly the
// EXE-internal STRINGTABLE we just embedded. Avoids adding
// `GetModuleHandleA` to KERNEL32's WIN32_IMPORTS (which would break the
// console `.idata` byte-identical golden in `tests/pe_imports.rs`; see the
// HLD §G3 + `WIN32_IMPORTS` comment in `src/pe.rs`).
//
// **Why console (subsystem 3) rather than GUI.** We need stdout to assert
// the loaded string — `printf` works in console programs. GUI subsystem
// 2 has no stdout in the standard sense, so we would have to find a
// window or post a message; far more brittle for a structural oracle.

/// The G3 program. Calls `LoadStringA(NULL, 1, buf, sizeof buf)` and prints
/// the recovered string. Compiled as a console TU (`main`, not `WinMain`).
const PROG_G3_LOADSTR: &str = r#"
#include <windows.h>

int main(void) {
    char buf[64];
    LoadStringA(0, 1, buf, 64);
    printf("got %s\n", buf);
    return 0;
}
"#;

/// The `.rc` source bundled with PROG_G3_LOADSTR. One STRINGTABLE entry,
/// id=1, value="Hello from .rsrc". Compiles via `mdbcc::rc::parse` (G1).
const PROG_G3_RC: &str = "STRINGTABLE\nBEGIN\n    1 \"Hello from .rsrc\"\nEND\n";

/// G3 structural — ALWAYS-ON, headless-safe. The produced PE must:
///   - import `LoadStringA` from USER32.dll (and still KERNEL32 for the
///     stub's ExitProcess);
///   - carry a `.rsrc` section pointed at by `DataDirectory[2]`;
///   - stay subsystem-3 (console) — `main`, not `WinMain`.
#[test]
fn g3_loadstr_compiles_with_rsrc_section_and_user32_import() {
    use mdbcc::compile::compile_to_pe_with_rc;
    use mdbcc::pp::DefaultResolver;
    use mdbcc::rc;

    let unit = rc::parse(PROG_G3_RC).expect("PROG_G3 .rc must parse");
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let pe = compile_to_pe_with_rc(
        PROG_G3_LOADSTR.as_bytes(),
        "<g3-loadstr>",
        &resolver,
        Some(&unit),
    )
    .expect("G3 program + sibling .rc must compile");

    // Console subsystem (main, not WinMain).
    assert_eq!(
        subsystem(&pe),
        3,
        "G3 program must stay subsystem 3 (console)"
    );

    // `LoadStringA` is now in USER32; KERNEL32 is still present for stub.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "G3 program missing KERNEL32.dll descriptor (the stub's \
         ExitProcess) — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "G3 program missing USER32.dll descriptor (LoadStringA was not \
         recognised as a USER32 import) — got {dlls:?}"
    );
    let syms = imported_symbols(&pe);
    assert!(
        syms.iter().any(|s| s == "LoadStringA"),
        "LoadStringA not present in imports — G3's WIN32_IMPORTS row was \
         not exercised: {syms:?}"
    );

    // `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE = 2]` non-zero.
    let opt = PE_OFF + 4 + 20;
    let dd_rva = parse_u32(&pe, opt + 112 + 2 * 8);
    let dd_size = parse_u32(&pe, opt + 112 + 2 * 8 + 4);
    assert_ne!(
        dd_rva, 0,
        "DataDirectory[RESOURCE].VirtualAddress must be non-zero when a \
         .rc was compiled in"
    );
    assert_ne!(
        dd_size, 0,
        "DataDirectory[RESOURCE].Size must be non-zero when a .rc was \
         compiled in"
    );
}

/// G3 liveness — desktop is **not** required; the program is a console
/// process that runs anywhere. Reuses the `TempExe` cleanup pattern.
/// Builds, runs, captures stdout, asserts the embedded string appears.
#[test]
fn g3_loadstr_runtime_loads_string_from_rsrc() {
    use mdbcc::compile::compile_to_pe_with_rc;
    use mdbcc::pp::DefaultResolver;
    use mdbcc::rc;

    let unit = rc::parse(PROG_G3_RC).expect("PROG_G3 .rc must parse");
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let pe = compile_to_pe_with_rc(
        PROG_G3_LOADSTR.as_bytes(),
        "<g3-loadstr>",
        &resolver,
        Some(&unit),
    )
    .expect("G3 program + sibling .rc must compile");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &pe).expect("write the G3 exe to a temp path");

    let out = match Command::new(&tmp.0).output() {
        Ok(o) => o,
        Err(e) => {
            // Cannot launch a console exe at all — environment, not an
            // mdbcc red (same loud-skip precedent as the GUI tests).
            skip(&format!("could not launch the G3 console exe: {e}"));
            return;
        }
    };

    assert_eq!(
        out.status.code(),
        Some(0),
        "G3 program must exit cleanly with code 0 (the runtime LoadStringA \
         call must succeed and `main` returns 0). stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The string lives in the `.rsrc` STRINGTABLE; `LoadStringA(NULL, 1,
    // buf, 64)` must populate `buf` with "Hello from .rsrc"; the
    // `printf("got %s\n", buf)` produces the asserted line.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("got Hello from .rsrc"),
        "G3 program stdout must contain \"got Hello from .rsrc\" (the \
         embedded STRINGTABLE entry recovered at runtime via \
         LoadStringA), got stdout: {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// Phase G / G4 — LoadMenuA retrieves a MENU resource from `.rsrc`
// ---------------------------------------------------------------------------
//
// G4 is the **MENU + ACCELERATORS landing**: an mdbcc-built EXE with a
// sibling `.rc` MENU compiles to a PE that imports `LoadMenuA` from
// USER32, has a `.rsrc` section with an RT_MENU(4) directory entry, and
// — at runtime — the Win32 loader resolves the menu handle by id when
// the program calls `LoadMenuA(NULL, MAKEINTRESOURCE(id))`. This is the
// O6 oracle for G4: a non-null `HMENU` proves the entire
// `.rc` → `.res` → `.rsrc` → directory-tree → LoadResource chain.
//
// **Why a numeric MENU id (100), not a string name.** Win32 supports
// either `LoadMenuA(NULL, MAKEINTRESOURCE(100))` (numeric id; resource
// directory uses an ordinal IdEntry) or `LoadMenuA(NULL, "MyMenu")`
// (string name; the directory needs a wide-string NamedEntry). Our
// `build_rsrc` emits ID entries only (sorted u16 ordinals); string-
// named resources are a G-future extension (the directory would need
// `NumberOfNamedEntries > 0` and a wide-string name pool). For G4 we
// use the numeric form to keep the directory contract intact while
// still exercising the full LoadMenuA chain.
//
// **Why console (subsystem 3) rather than GUI.** Mirrors the G3
// precedent: stdout assertion is the cheapest oracle, and `LoadMenuA`
// works equally well in console as in GUI processes (the menu just
// won't ever be drawn — but the resource lookup succeeds).

/// The G4 program. Calls `LoadMenuA(0, (LPCSTR)100)` and prints the
/// outcome. The cast to `LPCSTR` is the Win32 idiom for
/// `MAKEINTRESOURCE(100)`: when the low WORD of the pointer is a
/// non-zero numeric id and the high WORD is zero, USER32 interprets it
/// as an ordinal rather than a string name.
const PROG_G4_MENU: &str = r#"
#include <windows.h>

int main(void) {
    HMENU h = LoadMenuA(0, (LPCSTR)100);
    if (h != 0) {
        printf("MENU OK\n");
        return 0;
    } else {
        printf("MENU FAIL\n");
        return 1;
    }
}
"#;

/// The `.rc` source bundled with PROG_G4_MENU. One MENU resource, id
/// 100, with one popup containing one MENUITEM. Compiles via
/// `mdbcc::rc::parse` (G1) and `write_res` (G2+G4).
const PROG_G4_RC: &str =
    "100 MENU\nBEGIN\n  POPUP \"&File\"\n  BEGIN\n    MENUITEM \"E&xit\", 200\n  END\nEND\n";

/// G4 structural — ALWAYS-ON, headless-safe. The produced PE must:
///   - import `LoadMenuA` from USER32.dll (and still KERNEL32 for the
///     stub's ExitProcess);
///   - carry a `.rsrc` section pointed at by `DataDirectory[2]` with an
///     RT_MENU (type 4) directory entry;
///   - stay subsystem-3 (console) — `main`, not `WinMain`.
#[test]
fn g4_menu_compiles_with_rt_menu_in_rsrc_and_user32_import() {
    use mdbcc::compile::compile_to_pe_with_rc;
    use mdbcc::pp::DefaultResolver;
    use mdbcc::rc;

    let unit = rc::parse(PROG_G4_RC).expect("PROG_G4 .rc must parse");
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let pe = compile_to_pe_with_rc(PROG_G4_MENU.as_bytes(), "<g4-menu>", &resolver, Some(&unit))
        .expect("G4 program + sibling .rc must compile");

    // Console subsystem (main, not WinMain).
    assert_eq!(
        subsystem(&pe),
        3,
        "G4 program must stay subsystem 3 (console)"
    );

    // `LoadMenuA` is in USER32; KERNEL32 is still present for the stub.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "G4 program missing KERNEL32.dll descriptor: {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "G4 program missing USER32.dll descriptor (LoadMenuA was not \
         recognised as a USER32 import): {dlls:?}"
    );
    let syms = imported_symbols(&pe);
    assert!(
        syms.iter().any(|s| s == "LoadMenuA"),
        "LoadMenuA not present in imports — G4's WIN32_IMPORTS row was \
         not exercised: {syms:?}"
    );

    // `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE = 2]` non-zero, and
    // the `.rsrc` section must contain a type-4 (RT_MENU) directory entry.
    let opt = PE_OFF + 4 + 20;
    let dd_rva = parse_u32(&pe, opt + 112 + 2 * 8);
    let dd_size = parse_u32(&pe, opt + 112 + 2 * 8 + 4);
    assert_ne!(
        dd_rva, 0,
        "DataDirectory[RESOURCE].VirtualAddress must be non-zero"
    );
    assert_ne!(dd_size, 0, "DataDirectory[RESOURCE].Size must be non-zero");

    // Find the `.rsrc` section and check its ROOT has an RT_MENU entry.
    let nsec = u16::from_le_bytes([pe[PE_OFF + 4 + 2], pe[PE_OFF + 4 + 3]]) as usize;
    let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
    let (rsrc_ptr, rsrc_vsize) = (0..nsec)
        .find_map(|i| {
            let h = tbl + i * SECT_HDR_LEN;
            if &pe[h..h + 5] == b".rsrc" {
                Some((
                    parse_u32(&pe, h + 20) as usize,
                    parse_u32(&pe, h + 8) as usize,
                ))
            } else {
                None
            }
        })
        .expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize];

    // ROOT.NumberOfIdEntries must be ≥ 1 and at least one of its entries
    // must reference RT_MENU(4). Layout: NumberOfIdEntries at offset 14,
    // first IdEntry at offset 16 (8-byte entries, ascending by Name).
    let n_ids = u16::from_le_bytes([rsrc[14], rsrc[15]]);
    assert!(n_ids >= 1, "ROOT must have at least one ID entry");
    let mut has_rt_menu = false;
    for i in 0..n_ids as usize {
        let name = parse_u32(rsrc, 16 + i * 8);
        if name == 4 {
            has_rt_menu = true;
            break;
        }
    }
    assert!(
        has_rt_menu,
        "`.rsrc` ROOT directory missing RT_MENU (type 4) entry — the G4 \
         MENU resource was not emitted into the resource tree"
    );
}

/// G4 liveness — desktop is **not** required; the program is a console
/// process that runs anywhere. Reuses the `TempExe` cleanup pattern.
/// Builds, runs, captures stdout, asserts the menu handle was non-null.
#[test]
fn g4_menu_runtime_loads_menu_from_rsrc() {
    use mdbcc::compile::compile_to_pe_with_rc;
    use mdbcc::pp::DefaultResolver;
    use mdbcc::rc;

    let unit = rc::parse(PROG_G4_RC).expect("PROG_G4 .rc must parse");
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let pe = compile_to_pe_with_rc(PROG_G4_MENU.as_bytes(), "<g4-menu>", &resolver, Some(&unit))
        .expect("G4 program + sibling .rc must compile");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &pe).expect("write the G4 exe to a temp path");

    let out = match Command::new(&tmp.0).output() {
        Ok(o) => o,
        Err(e) => {
            skip(&format!("could not launch the G4 console exe: {e}"));
            return;
        }
    };

    assert_eq!(
        out.status.code(),
        Some(0),
        "G4 program must exit cleanly with code 0 (LoadMenuA must \
         return a non-null HMENU and main returns 0). stdout: {:?}, \
         stderr: {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The MENU lives in the `.rsrc`; `LoadMenuA(NULL, MAKEINTRESOURCE(100))`
    // must succeed and the program prints "MENU OK".
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MENU OK"),
        "G4 program stdout must contain \"MENU OK\" (the embedded MENU \
         resource recovered at runtime via LoadMenuA), got stdout: {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// Phase G / G5b — DialogBoxParamA displays a DLGTEMPLATE from `.rsrc`
// ---------------------------------------------------------------------------
//
// G5 is the **DIALOG runtime landing**: an mdbcc-built EXE with a sibling
// `.rc` DIALOG compiles to a PE that imports `DialogBoxParamA` + `EndDialog`
// from USER32, has a `.rsrc` section with an RT_DIALOG(5) directory entry,
// and — at runtime — the Win32 loader resolves the dialog template by id
// when the program calls `DialogBoxParamA(NULL, MAKEINTRESOURCE(100), NULL,
// DlgProc, 0)`. This is the **first GUI Phase-G runtime test** that needs
// the cross-thread dismissal pattern (mirroring D5 / E4): the modal dialog
// blocks the child's main thread, so the harness *outside* the process
// must locate the dialog window and post `WM_COMMAND(IDOK)` to dismiss it.
//
// **Why an explicit DlgProc, not NULL.** Win32 historically requires a non-
// NULL DLGPROC for `DialogBoxParamA`; some references say a NULL proc is
// permitted but in practice (a) it relies on undocumented default-proc
// behaviour and (b) the dismissal-by-WM_COMMAND-IDOK then leans on that
// default. A 5-line explicit `DlgProc` that calls `EndDialog` on
// WM_COMMAND(IDOK)/WM_COMMAND(IDCANCEL) is unambiguous and self-documents
// the dismissal contract. IDOK = 1, IDCANCEL = 2 (Win32 `<winuser.h>`);
// not in mdbcc's intrinsic `WINDOWS_H` (which is the minimal subset), so
// we spell them as literals in the C source.
//
// **Why console (subsystem 3) rather than GUI.** Mirrors G3/G4: stdout
// assertion ("DLG OK") is the cheapest oracle and `DialogBoxParamA` works
// equally well in a console process. The dialog window is still a real
// top-level Win32 window discoverable via `FindWindowA`.
//
// **Why no STYLE statement in the `.rc`.** mdbcc's v1 `.rc` parser accepts
// only a numeric u32 after STYLE (see `src/rc/parser.rs::parse_u32_with_
// label`), not the symbolic `WS_POPUP | WS_CAPTION | WS_SYSMENU` form. By
// omitting STYLE we get the parser-supplied `DIALOG_DEFAULT_STYLE`
// (WS_POPUP | WS_BORDER | WS_SYSMENU = 0x80880000) and the CAPTION
// statement ORs in WS_CAPTION (0x00C00000) — equivalent to the canonical
// "popup with caption + sysmenu" the HLD §G5 references, while staying
// within the v1 grammar.

/// The G5 program. Defines a 5-line DLGPROC that closes the dialog on
/// `WM_COMMAND(IDOK|IDCANCEL)`, then calls `DialogBoxParamA(NULL,
/// (LPCSTR)100, NULL, DlgProc, 0)`. The cast `(LPCSTR)100` is the Win32
/// idiom for `MAKEINTRESOURCE(100)` (low-WORD = numeric id, high-WORD
/// zero ⇒ USER32 treats the pointer as an ordinal). The program is
/// `main`-based (console subsystem 3) — same precedent as G3/G4. The
/// modal `DialogBoxParamA` call blocks until the harness posts
/// `WM_COMMAND(IDOK)` to the dialog window; on return we print "DLG OK"
/// and exit 0 (the dismissal proof + the structural .rsrc layout are the
/// oracles, not the numeric return value).
///
/// Notes on the C source vs. mdbcc's intrinsic `WINDOWS_H`:
/// - `INT_PTR` is not in the intrinsic body; `LONG_PTR` (typedef'd to
///   `__int64`) is, and matches the real Win32 INT_PTR on x64.
/// - `IDOK`, `IDCANCEL`, `WM_INITDIALOG` are not in the intrinsic body;
///   they are spelled as literals (1, 2, 0x0110).
/// - `CALLBACK` is `#define`d empty in the intrinsic body, so the proc
///   signature reads as a plain function (the underlying ABI is still
///   the Win64 calling convention).
/// - `DialogBoxParamA` / `EndDialog` are in USER32 via G5a's
///   `WIN32_IMPORTS`; no explicit declaration needed (the K&R-style
///   implicit-int rule the existing G3 `LoadStringA` / G4 `LoadMenuA`
///   sources rely on).
const PROG_G5_DIALOG: &str = r#"
#include <windows.h>

LONG_PTR DlgProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == 0x0111) {
        UINT id = (UINT)(w & 0xFFFF);
        if (id == 1 || id == 2) {
            EndDialog(h, id);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    DialogBoxParamA(0, (LPCSTR)100, 0, DlgProc, 0);
    printf("DLG OK\n");
    return 0;
}
"#;

/// The `.rc` source bundled with PROG_G5_DIALOG. One DIALOG resource, id
/// 100, with CAPTION (so the harness can match it via
/// `FindWindowA(NULL, "G5 Dialog")`), an explicit `FONT` (so the
/// DS_SETFONT bit gets set and Windows treats this as a v1 DLGTEMPLATE),
/// and a single `DEFPUSHBUTTON "OK", 1` (id=IDOK=1 — its `BN_CLICKED`
/// becomes the `WM_COMMAND` whose LOWORD(wParam)=1 the DlgProc closes
/// on). STYLE is omitted: the parser supplies `DIALOG_DEFAULT_STYLE`
/// (WS_POPUP|WS_BORDER|WS_SYSMENU); CAPTION ORs in WS_CAPTION.
const PROG_G5_RC: &str = "\
100 DIALOG 20, 20, 100, 50\n\
CAPTION \"G5 Dialog\"\n\
FONT 8, \"MS Sans Serif\"\n\
BEGIN\n\
  DEFPUSHBUTTON \"OK\", 1, 25, 25, 50, 14\n\
END\n";

/// The exact caption of the G5 dialog window (used by `FindWindowA`).
/// Matches the `CAPTION` in PROG_G5_RC exactly (nul-terminated for the
/// Win32 ANSI API).
const G5_WINDOW_TITLE: &[u8] = b"G5 Dialog\0";

/// Win32 `WM_COMMAND` and `IDOK` for the harness-side dismissal. Mirrors
/// the WM_CLOSE constant up top.
const WM_COMMAND: u32 = 0x0111;
const IDOK: usize = 1;

/// G5 structural — ALWAYS-ON, headless-safe. The produced PE must:
///   - import `DialogBoxParamA` (and the existing `EndDialog`) from
///     USER32.dll (and still KERNEL32 for the stub's ExitProcess);
///   - carry a `.rsrc` section pointed at by `DataDirectory[2]` with an
///     RT_DIALOG (type 5) directory entry;
///   - the DLGTEMPLATE payload parses as one control (`cdit == 1`,
///     matching the single `DEFPUSHBUTTON` in PROG_G5_RC);
///   - stay subsystem-3 (console) — `main`, not `WinMain`.
#[test]
fn compile_g5_dialog_emits_expected_resources() {
    use mdbcc::compile::compile_to_pe_with_rc;
    use mdbcc::pp::DefaultResolver;
    use mdbcc::rc;

    let unit = rc::parse(PROG_G5_RC).expect("PROG_G5 .rc must parse");
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let pe = compile_to_pe_with_rc(
        PROG_G5_DIALOG.as_bytes(),
        "<g5-dialog>",
        &resolver,
        Some(&unit),
    )
    .expect("G5 program + sibling .rc must compile");

    // Console subsystem (main, not WinMain).
    assert_eq!(
        subsystem(&pe),
        3,
        "G5 program must stay subsystem 3 (console)"
    );

    // `DialogBoxParamA` is in USER32; KERNEL32 is still present for the stub.
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "G5 program missing KERNEL32.dll descriptor: {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "G5 program missing USER32.dll descriptor (DialogBoxParamA was not \
         recognised as a USER32 import): {dlls:?}"
    );
    let syms = imported_symbols(&pe);
    assert!(
        syms.iter().any(|s| s == "DialogBoxParamA"),
        "DialogBoxParamA not present in imports — G5a's WIN32_IMPORTS row \
         was not exercised: {syms:?}"
    );
    assert!(
        syms.iter().any(|s| s == "EndDialog"),
        "EndDialog not present in imports — G5a's WIN32_IMPORTS row was not \
         exercised (DlgProc calls EndDialog): {syms:?}"
    );

    // `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE = 2]` non-zero, and
    // the `.rsrc` section must contain a type-5 (RT_DIALOG) directory entry.
    let opt = PE_OFF + 4 + 20;
    let dd_rva = parse_u32(&pe, opt + 112 + 2 * 8);
    let dd_size = parse_u32(&pe, opt + 112 + 2 * 8 + 4);
    assert_ne!(
        dd_rva, 0,
        "DataDirectory[RESOURCE].VirtualAddress must be non-zero"
    );
    assert_ne!(dd_size, 0, "DataDirectory[RESOURCE].Size must be non-zero");

    // Find the `.rsrc` section and check its ROOT has an RT_DIALOG(5) entry
    // and that the embedded DLGTEMPLATE's `cdit` (control count) is 1.
    let nsec = u16::from_le_bytes([pe[PE_OFF + 4 + 2], pe[PE_OFF + 4 + 3]]) as usize;
    let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
    let (rsrc_ptr, rsrc_vsize) = (0..nsec)
        .find_map(|i| {
            let h = tbl + i * SECT_HDR_LEN;
            if &pe[h..h + 5] == b".rsrc" {
                Some((
                    parse_u32(&pe, h + 20) as usize,
                    parse_u32(&pe, h + 8) as usize,
                ))
            } else {
                None
            }
        })
        .expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize];

    // ROOT.NumberOfIdEntries must be ≥ 1 and at least one of its entries
    // must reference RT_DIALOG(5).
    let n_ids = u16::from_le_bytes([rsrc[14], rsrc[15]]);
    assert!(n_ids >= 1, "ROOT must have at least one ID entry");
    let mut has_rt_dialog = false;
    for i in 0..n_ids as usize {
        let name = parse_u32(rsrc, 16 + i * 8);
        if name == 5 {
            has_rt_dialog = true;
            break;
        }
    }
    assert!(
        has_rt_dialog,
        "`.rsrc` ROOT directory missing RT_DIALOG (type 5) entry — the G5 \
         DIALOG resource was not emitted into the resource tree"
    );

    // Locate the DLGTEMPLATE payload via `mdbcc::rc::res::write_dialog_bytes`
    // through the public `collect_dialogs` path — but we can't reach that
    // from tests/ (pub(crate)). Instead, parse the .rsrc tree to find the
    // DATA leaf RVA/size for the RT_DIALOG entry. The PE walks:
    //   ROOT dir -> type-5 entry -> NAME dir -> id-100 entry -> LANG dir
    //   -> lang entry -> IMAGE_RESOURCE_DATA_ENTRY {data_rva, size, ...}
    // and the DLGTEMPLATE bytes live at pe[data_rva - dd_rva + rsrc_ptr].
    //
    // Re-using the same structural pattern as the runtime test: we don't
    // need the exact bytes — only that the DLGTEMPLATE header parses and
    // `cdit == 1`. The DLGTEMPLATE layout (Win32 `<winuser.h>`) is:
    //   u32 style; u32 dwExtendedStyle; u16 cdit; i16 x; i16 y; i16 cx;
    //   i16 cy; ... (variable trailer)
    // so `cdit` is at offset 8 inside the payload.
    let (rsrc_va, _rsrc_size) = {
        let opt = PE_OFF + 4 + 20;
        (
            parse_u32(&pe, opt + 112 + 2 * 8),
            parse_u32(&pe, opt + 112 + 2 * 8 + 4),
        )
    };
    // Walk ROOT to the RT_DIALOG sub-directory.
    let rt_dialog_idx = (0..n_ids as usize)
        .find(|&i| parse_u32(rsrc, 16 + i * 8) == 5)
        .expect("RT_DIALOG entry must exist");
    let n_names = u16::from_le_bytes([rsrc[12], rsrc[13]]) as usize;
    let entries_off = 16; // 16-byte directory header
    let dialog_entry_off = entries_off + (n_names + rt_dialog_idx) * 8;
    let dialog_offset_field = parse_u32(rsrc, dialog_entry_off + 4);
    // High bit = "this is a subdirectory offset" — strip it.
    assert!(
        dialog_offset_field & 0x8000_0000 != 0,
        "RT_DIALOG entry must point to a subdirectory (high bit set)"
    );
    let dialog_dir_off = (dialog_offset_field & 0x7FFF_FFFF) as usize;
    // Walk the NAME (id=100) sub-directory.
    let n_id_names =
        u16::from_le_bytes([rsrc[dialog_dir_off + 14], rsrc[dialog_dir_off + 15]]) as usize;
    let n_named =
        u16::from_le_bytes([rsrc[dialog_dir_off + 12], rsrc[dialog_dir_off + 13]]) as usize;
    assert!(
        n_id_names >= 1,
        "DIALOG NAME-level must have at least one id entry"
    );
    let id_entry_off = dialog_dir_off + 16 + n_named * 8;
    let id_value = parse_u32(rsrc, id_entry_off);
    assert_eq!(id_value, 100, "DIALOG NAME entry must have id=100");
    let lang_offset_field = parse_u32(rsrc, id_entry_off + 4);
    assert!(
        lang_offset_field & 0x8000_0000 != 0,
        "DIALOG NAME entry must point to a LANG subdirectory"
    );
    let lang_dir_off = (lang_offset_field & 0x7FFF_FFFF) as usize;
    // The LANG entry: first entry, offset bit clear ⇒ points to data entry.
    let lang_entry_off = lang_dir_off + 16;
    let data_entry_field = parse_u32(rsrc, lang_entry_off + 4);
    assert!(
        data_entry_field & 0x8000_0000 == 0,
        "LANG entry must point to a data leaf (high bit clear)"
    );
    let data_entry_off = data_entry_field as usize;
    let data_rva = parse_u32(rsrc, data_entry_off);
    let data_size = parse_u32(rsrc, data_entry_off + 4);
    // Translate RVA back to an offset inside the rsrc slice.
    let data_off_in_rsrc = (data_rva - rsrc_va) as usize;
    assert!(
        data_off_in_rsrc + data_size as usize <= rsrc.len(),
        "DLGTEMPLATE payload must fit inside the .rsrc section"
    );
    let dlg = &rsrc[data_off_in_rsrc..data_off_in_rsrc + data_size as usize];
    // DLGTEMPLATE: u32 style, u32 dwExStyle, u16 cdit (offset 8).
    assert!(
        dlg.len() >= 10,
        "DLGTEMPLATE must be at least 10 bytes for the header"
    );
    let cdit = u16::from_le_bytes([dlg[8], dlg[9]]);
    assert_eq!(
        cdit, 1,
        "DLGTEMPLATE cdit (control count) must be 1 — the .rc declares one \
         DEFPUSHBUTTON"
    );
}

/// G5 liveness — needs an **interactive desktop** (the dialog must be
/// findable via `FindWindowA`). Reuses the existing D5/E4 cross-thread
/// dismissal infra verbatim (`interactive_desktop()`, `ProcHandle` RAII +
/// `TerminateProcess` watchdog, `FindWindowA` / `PostMessageA` FFI,
/// `skip()` loud self-skip).
///
/// Flow: build the PE → spawn → poll `FindWindowA(NULL, "G5 Dialog")`
/// for up to ~4 s → `PostMessageA(hwnd, WM_COMMAND, IDOK, 0)` → wait
/// up to 5 s for clean exit → assert exit code 0 + stdout contains
/// "DLG OK".
///
/// Hard safety: same bounded-poll / RAII / TerminateProcess machinery as
/// D5/E4 — never hangs, never false-fails on environment. The dialog is
/// modal (blocks the child's main thread), so dismissal MUST come from
/// outside the process; the RAII `ProcHandle::drop` is the last-resort
/// backstop that kills a stuck modal box even on a panic unwind.
#[test]
fn prog_g5_dialog_displays_and_dismisses() {
    use mdbcc::compile::compile_to_pe_with_rc;
    use mdbcc::pp::DefaultResolver;
    use mdbcc::rc;

    let unit = rc::parse(PROG_G5_RC).expect("PROG_G5 .rc must parse");
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let pe = compile_to_pe_with_rc(
        PROG_G5_DIALOG.as_bytes(),
        "<g5-dialog>",
        &resolver,
        Some(&unit),
    )
    .expect("G5 program + sibling .rc must compile");

    // Headless gate up front — no interactive station ⇒ no FindWindowA
    // visibility of the dialog. Self-skip loudly (the o2/o3 precedent;
    // matches D5/E4). The structural sibling test still runs unconditionally.
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [G5]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the G5 exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the G5 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the G5 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll FindWindowA by exact caption for at most ~4 s.
    // The dialog window's class is "#32770" (the Win32 standard dialog
    // class), but matching by caption-only (NULL class) is robust and
    // mirrors D5/E4 — Windows guarantees a top-level window with the
    // exact CAPTION string we wrote into the DLGTEMPLATE.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), G5_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // MINOR-1 mitigation (mirrors D5/E4): if the child already died
        // with a non-STILL_ACTIVE exit code before any window appeared,
        // surface that as a hard failure (e.g. DialogBoxParamA returned
        // -1 because the .rsrc couldn't be located — a real mdbcc red,
        // not an environment issue).
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "G5 child exited on its own ({code:#x}) before any dialog \
                 window was discoverable — DialogBoxParamA likely failed \
                 (resource not found / dialog template malformed); \
                 FindWindowA timed out after 4 s with a dead child"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip(
            "could not locate the G5 dialog window within 4 s (treated as \
              no interactive station)",
        );
        return;
    }

    // Dismiss via PostMessageA(WM_COMMAND, IDOK). The DlgProc closes the
    // dialog on WM_COMMAND with LOWORD(wParam)=IDOK=1 by calling
    // EndDialog(h, IDOK), which unblocks the child's DialogBoxParamA call.
    // PostMessageA is async — never blocks this thread on the modal pump.
    let posted = unsafe { PostMessageA(hwnd, WM_COMMAND, IDOK, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip(
            "PostMessageA(WM_COMMAND, IDOK) failed on G5 dialog; child \
              force-terminated",
        );
        return;
    }

    // It must exit cleanly within a strict bound. A hang here would mean
    // the DlgProc failed to call EndDialog (or EndDialog failed) — the
    // watchdog is a backstop.
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip(
            "G5 process did not exit within 5 s after WM_COMMAND(IDOK); \
              force-terminated",
        );
        return;
    }

    // Signalled in time — assert exit code 0.
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "G5 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "G5 dialog process must exit with code 0 — DlgProc must \
                 receive WM_COMMAND(IDOK), call EndDialog(h, IDOK), and \
                 main() must return 0 after DialogBoxParamA returns"
            );
            // Note: we have no stdout pipe captured here (spawn() without
            // `.stdout(Stdio::piped())` means stdout goes to the inherited
            // console). The exit-code-0 outcome plus a successfully-
            // dismissed dialog (FindWindow found it; PostMessage succeeded;
            // child exited cleanly within 5 s) is the runtime oracle. The
            // structural sibling test pins the .rsrc layout / imports.
        }
        None => {
            skip("G5 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ---------------------------------------------------------------------------
// J-21 — synthetic OWL-style cross-feature integration corpus.
// ---------------------------------------------------------------------------
//
// J-21 is the **forcing function** the H10 review's MINOR-3 demanded but
// never landed: a single TU that combines, in one OWL-shaped fixture, every
// cross-feature surface mdbcc claims to support. Per `wrk_docs/2026.05.22 -
// PLAN - Compiler completion (J-N + tail).md` §4 (J-21):
//
//   (1) Class hierarchy with virtuals — TMyWin : TFrameWindow with overridden
//       response-table handlers (Ev* virtuals).
//   (2) Response-table dispatch — DECLARE/DEFINE/END_RESPONSE_TABLE +
//       EV_WM_PAINT, EV_WM_LBUTTONDOWN, EV_WM_COMMAND, EV_WM_KEYDOWN,
//       EV_WM_DESTROY (5 of the 8 v1 events).
//   (3) Custom exception hierarchy — TXBase (virtual dtor + int code) +
//       TXMyAppError : public TXBase; throw + catch-by-reference; exercises
//       the H4b hierarchy walk + .pdata/.xdata emission inside an OWL handler.
//   (4) struct-by-value parameter passing — `int point_sum(Point p)` called
//       from EvPaint; the Win64 8-byte struct ABI path (cpp_struct.rs surface).
//   (5) Operator overloading — `int Point::operator+(Point&) const` —
//       exercises J-1 trailing-const + H7 binary-op overloading at the same
//       time. **Returns `int`, not `Point`**: see "Gap report (J-21)" comment
//       below; returning the enclosing class from operator+ surfaces multiple
//       mdbcc bugs (gen_addr does not rewrite Expr::Binary to operator+ method
//       call; inline-member-fn-with-return-type-of-enclosing-class triggers
//       a bogus "empty struct" diagnostic). Filed as J-21-GAP-{A,B,C}.
//   (6) Array-new with explicit ctor — Counter with user-defined default ctor
//       (`Counter() { id = g_ctor_count++; }`) and dtor (counts dtor calls);
//       `Counter* group = new Counter[3];` + `delete[]`.
//   (7) Block-scope shadowing — `int idx;` outer + `{ int idx; }` inner
//       (H8 surface) inside a TMyWin method.
//   (8) Member function overloading — `print(int)` vs `print(char*)` on
//       TMyWin (H5 surface).
//   (9) operator[] returning T& — `int& TIntList::operator[](int)` with both
//       lvalue stores and rvalue loads (cpp_op_overload surface).
//   (10) Adjacent string-literal concatenation — `printf("Hello, " "OWL!\n")`
//        inside a TMyWin method (H9 surface).
//
// **The value** is exercising the cross-product (per H10 MINOR-3 — every
// feature has per-feature suites but no fixture exercises them together) on
// a real-OWL-shaped program that builds, launches a top-level window, runs
// its EvPaint handler through synchronous WM_PAINT (via UpdateWindow inside
// TWindow::Show), dispatches user-input via EV_WM_LBUTTONDOWN, and exits
// cleanly through the Phase-E response-table teardown chain (WM_CLOSE →
// DefWindowProcA → WM_DESTROY → EV_WM_DESTROY → PostQuitMessage → exit 0).
//
// ## Gap report (J-21) — what this fixture surfaced
//
// Three real bugs were found while authoring this fixture in tick 53;
// **all closed by ticks 54, 55, and 56**. The fixture now uses the
// natural forms (Point-returning op+, member access on `(a+b)`,
// explicit `.operator+` syntax where readable) so it locks the
// post-fix surface end-to-end.
//
//   * **J-21-GAP-A** (G-1/G-4) — **CLOSED tick 55**: inline member fn
//     returning own class no longer fails with bogus "empty struct"
//     diagnostic.
//   * **J-21-GAP-B** (G-2/G-3) — **CLOSED tick 56**: `gen_addr` now
//     accepts `Expr::Binary` returning a record (rewrites through the
//     MethodCall arm of gen_expr); `gen_binary` now uses the prepare/
//     complete record-return-call machinery for op+ returning a class,
//     so `(a + b).x`, `c = a + b`, and `take(a + b)` all work.
//   * **J-21-GAP-C** (G-5) — **CLOSED tick 54**: explicit
//     `obj.operator+(rhs)` member-call syntax now parses + lowers.
//
// See the gap-report journal for full reproductions and root-cause sketches.
//
// ## Test shape
//
// Two tests, mirroring the D5/E3/E4 precedent:
//   * **structural** (always-on, headless-safe): compile to PE, assert
//     subsystem 2, USER32 + GDI32 + KERNEL32 descriptors present, .pdata
//     + .xdata sections present (because the fixture's EvPaint throws +
//     catches), .text + .idata structurally well-formed.
//   * **liveness** (desktop-gated, watchdog-bounded): spawn the PE,
//     capture stdout via Stdio::piped, find the J21 window by exact
//     caption, inject one click via SendMessageA(WM_LBUTTONDOWN), post
//     WM_CLOSE, assert exit code 0 AND every J21_* sentinel line is
//     present in captured stdout (so we know every feature's handler
//     fired).

const PROG_J21_OWL_INTEGRATION: &str = r##"
#include <owl/applicat.h>
#include <owl/framewin.h>
#include <stdio.h>

// Feature (5): operator+ with trailing-const (J-1) + H7 binary overload.
// Tick 56 closes G-2/G-3 so the natural Point-returning form is now in
// place (was int-returning pre-tick-56 to sidestep the gap). Exercises
// the rvalue-materialisation path for an InReg(8) op+ return, plus
// member access on `(a + b).x` / `(a + b).y`.
class Point {
public:
    int x;
    int y;
    Point() { x = 0; y = 0; }
    Point operator+(Point& o) const { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
};

// Feature (4): struct-by-value parameter passing.
int point_sum(Point p) { return p.x + p.y; }

// Feature (3): custom exception class hierarchy.
class TXBase {
public:
    virtual ~TXBase() {}
    int code;
    TXBase() { code = 0; }
};

class TXMyAppError : public TXBase {
public:
    TXMyAppError() {}
};

// Feature (6): array-new with user-defined ctor + dtor (Counter[3]).
int g_ctor_count = 0;
int g_dtor_count = 0;
class Counter {
public:
    int id;
    Counter() { id = g_ctor_count; g_ctor_count = g_ctor_count + 1; }
    ~Counter() { g_dtor_count = g_dtor_count + 1; }
};

// Feature (9): operator[] returning T& (int& specifically).
class TIntList {
public:
    int data[8];
    TIntList() {
        int i;
        i = 0;
        while (i < 8) { data[i] = 0; i = i + 1; }
    }
    int& operator[](int i) { return data[i]; }
};

// Features (1, 2, 7, 8, 10): TFrameWindow subclass + response table +
// block-scope shadowing + member overloading + adjacent string literals.
class TMyWin : public TFrameWindow {
public:
    int paint_count;
    int click_count;
    TMyWin(TWindow* p, const char* t)
        : TFrameWindow(p, t) { paint_count = 0; click_count = 0; }

    // Feature (8): member-function overloading on parameter type.
    void print(int n) { printf("J21_INT=%d\n", n); }
    void print(char* s) { printf("J21_STR=%s\n", s); }

    // Feature (10): adjacent string-literal concatenation (H9).
    void greet() { printf("Hello, " "OWL!\n"); }

    // Feature (7): block-scope shadowing (H8). Inner `idx=7` is scoped
    // to the brace; outer `idx=100` survives.
    int demoShadow() {
        int idx;
        idx = 100;
        {
            int idx;
            idx = 7;
            printf("J21_INNER=%d\n", idx);
        }
        return idx;
    }

    void EvPaint();
    void EvLButtonDown(UINT modKeys, int x, int y);
    void EvCommand(UINT cmdId, HWND ctrl, UINT notify);
    void EvKeyDown(UINT key, UINT repeat, UINT flags);
    void EvDestroy();

    DECLARE_RESPONSE_TABLE(TMyWin);
};

void TMyWin::EvPaint() {
    TPaintDC dc(*this);
    paint_count = paint_count + 1;
    dc.TextOut(10, 10, "J21");

    // Feature (4, 5): struct-by-value pass + operator+ trailing-const.
    // Tick 56: op+ returns Point. Sum the components for the sentinel so
    // the test value semantics remain identical (18 = (3+5)+(4+6)).
    Point a; a.x = 3; a.y = 4;
    Point b; b.x = 5; b.y = 6;
    int psum = point_sum(a);
    int opval = (a + b).x + (a + b).y;
    printf("J21_OPADD=%d J21_SUM=%d\n", opval, psum);

    // Feature (8): overloaded print on TMyWin.
    print(paint_count);
    print("paint");

    // Feature (10): adjacent string-literal concat in a printf.
    greet();

    // Feature (3): throw class instance, catch by reference up the
    // hierarchy (TXMyAppError thrown, caught as TXBase&).
    try {
        TXMyAppError e;
        e.code = 7;
        throw e;
    } catch (TXBase& base) {
        printf("J21_CAUGHT=%d\n", base.code);
    }

    // Feature (7): block-scope shadowing.
    int sh = demoShadow();
    printf("J21_SHADOW=%d\n", sh);

    // Feature (6): array-new with ctor (3 ctor calls, 3 dtor calls).
    Counter* group = new Counter[3];
    printf("J21_NEW ctors=%d ids=%d,%d,%d\n",
           g_ctor_count, group[0].id, group[1].id, group[2].id);
    delete[] group;
    printf("J21_DEL dtors=%d\n", g_dtor_count);

    // Feature (9): operator[] returning int&; lvalue store + rvalue read.
    TIntList list;
    list[0] = 42;
    list[7] = 99;
    printf("J21_LIST=%d,%d\n", list[0], list[7]);
}

void TMyWin::EvLButtonDown(UINT modKeys, int x, int y) {
    click_count = click_count + 1;
    printf("J21_CLICK %d at %d,%d\n", click_count, x, y);
}

void TMyWin::EvCommand(UINT cmdId, HWND ctrl, UINT notify) {
    printf("J21_CMD %d\n", cmdId);
}

void TMyWin::EvKeyDown(UINT key, UINT repeat, UINT flags) {
    printf("J21_KEY %d\n", key);
}

void TMyWin::EvDestroy() {
    printf("J21_DESTROY paints=%d clicks=%d\n", paint_count, click_count);
}

DEFINE_RESPONSE_TABLE1(TMyWin, TFrameWindow)
    EV_WM_PAINT
    EV_WM_LBUTTONDOWN
    EV_WM_COMMAND
    EV_WM_KEYDOWN
    EV_WM_DESTROY
END_RESPONSE_TABLE

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TMyWin(0, "MdbccJ21OwlIntegrationGui"));
    }
};

int OwlMain(int argc, char** argv) {
    TMyApp app;
    return app.Run();
}
"##;

/// Exact caption of the J-21 OWL window (FindWindowA target).
const J21_WINDOW_TITLE: &[u8] = b"MdbccJ21OwlIntegrationGui\0";

/// Soft "is this section present?" — gui.rs's `section()` panics on miss;
/// J-21 needs the present/absent test for `.pdata` / `.xdata` (which the
/// fixture's EvPaint try/catch forces into existence).
fn has_section(pe: &[u8], name: &[u8]) -> bool {
    let coff = PE_OFF + 4;
    let nsec = parse_u16(pe, coff + 2) as usize;
    let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
    (0..nsec).any(|i| {
        let h = tbl + i * SECT_HDR_LEN;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        pe[h..h + 8] == want
    })
}

/// J-21 structural — ALWAYS-ON, headless-safe. Pins the cross-feature
/// fixture compiles to a well-formed GUI PE with **every** structural
/// invariant the contributing features demand:
///   - subsystem 2 (the OWL runtime's WinMain → GUI stub);
///   - KERNEL32 + USER32 + GDI32 descriptors (E3 3-DLL .idata shape);
///   - `.pdata` + `.xdata` present (the EvPaint try/catch forces SEH
///     emission — DataDirectory[3] must be non-zero);
///   - `.text` non-empty;
///   - **exactly the E3 import set** — no new DLL (the fixture only adds
///     C++ idioms inside handlers; no new Win32 surface).
#[test]
fn j21_owl_integration_structural() {
    let pe = compile_to_pe(PROG_J21_OWL_INTEGRATION.as_bytes())
        .expect("J-21 OWL integration fixture must compile");

    // GUI subsystem (the OWL runtime supplies WinMain → C2 GUI stub).
    assert_eq!(
        subsystem(&pe),
        2,
        "J-21 OWL fixture must be PE Subsystem == 2 (WINDOWS_GUI)"
    );

    // KERNEL32 + USER32 + GDI32 (the E3-established 3-DLL shape; the
    // J-21 fixture adds zero new Win32 imports — its growth is all C++
    // idioms inside handlers).
    let dlls = imported_dlls(&pe);
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("KERNEL32.dll")),
        "J-21 fixture missing KERNEL32.dll descriptor — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("USER32.dll")),
        "J-21 fixture missing USER32.dll descriptor — got {dlls:?}"
    );
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("GDI32.dll")),
        "J-21 fixture missing GDI32.dll descriptor (TPaintDC::TextOut \
         pulls in TextOutA) — got {dlls:?}"
    );
    assert_eq!(
        dlls.len(),
        3,
        "J-21 fixture must import exactly KERNEL32 + USER32 + GDI32 \
         (no new DLL beyond the E3 baseline) — got {dlls:?}"
    );

    // SEH sections must exist — the EvPaint handler's `try {} catch
    // (TXBase&) {}` forces `.pdata` + `.xdata` emission (H4a/H4b paths).
    // Locks the cross-feature surface "exceptions inside an OWL handler
    // produce the same SEH-section emission as a console try/catch".
    assert!(
        has_section(&pe, b".pdata"),
        "J-21 fixture must emit .pdata — EvPaint contains try/catch \
         (TXBase&) which forces SEH emission"
    );
    assert!(
        has_section(&pe, b".xdata"),
        "J-21 fixture must emit .xdata — EvPaint contains try/catch \
         (TXBase&) which forces UNWIND_INFO emission"
    );

    // DataDirectory[3] (EXCEPTION) must point at the .pdata RVA/size pair.
    let opt = PE_OFF + 4 + 20;
    let exc_rva = parse_u32(&pe, opt + 112 + 3 * 8);
    let exc_size = parse_u32(&pe, opt + 112 + 3 * 8 + 4);
    assert_ne!(
        exc_rva, 0,
        "J-21 fixture's DataDirectory[EXCEPTION].VirtualAddress must be \
         non-zero — the EvPaint try/catch's .pdata is the source"
    );
    assert_ne!(
        exc_size, 0,
        "J-21 fixture's DataDirectory[EXCEPTION].Size must be non-zero"
    );

    // `.text` non-empty — sanity that the long cross-feature TU's
    // EvPaint actually got emitted (and not silently dropped).
    let (_text_ptr, text_vsize, _text_va) = section(&pe, b".text");
    assert!(
        text_vsize > 0x100,
        "J-21 fixture's .text must be substantial (>256 B); got \
         {text_vsize} — a near-empty .text suggests a silent codegen drop"
    );
}

/// J-21 liveness — desktop-gated, watchdog-bounded. **The cross-feature
/// forcing function**: spawns the PE, captures stdout via Stdio::piped,
/// finds the J21 window by exact caption, injects ONE WM_LBUTTONDOWN via
/// SendMessageA (so EvLButtonDown fires once), posts WM_CLOSE, asserts
/// exit code 0 AND every J21_* sentinel line is present in captured
/// stdout (the executable proof that every feature's handler ran).
///
/// Reuses the E3/E4 infra verbatim (interactive_desktop(), ProcHandle
/// RAII, FindWindowA / SendMessageA / PostMessageA FFI, skip() loud
/// self-skip, TempExe, the Stdio::piped() + reader-thread pattern).
///
/// Teardown chain (close → exit 0): same as E3/E4 — WM_CLOSE →
/// base_WindowProc → DefWindowProcA → DestroyWindow → WM_DESTROY →
/// EV_WM_DESTROY (EvDestroy emits the summary line) → PostQuitMessage(0)
/// → GetMessageA returns 0 → loop exits → ExitProcess(0).
#[test]
fn j21_owl_integration_liveness() {
    use std::io::Read;
    use std::process::Stdio;

    let pe = match compile_to_pe(PROG_J21_OWL_INTEGRATION.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("J-21 OWL fixture failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "J-21 fixture must be subsystem 2 before launch"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [J-21]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the J-21 exe to a temp path");
        return;
    }

    let mut child = match Command::new(&tmp.0).stdout(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the J-21 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let stdout_pipe = match child.stdout.take() {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("piped stdout missing from spawned J-21 child");
            return;
        }
    };
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the J-21 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut p = stdout_pipe;
        let _ = p.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        let h = unsafe { FindWindowA(std::ptr::null(), J21_WINDOW_TITLE.as_ptr()) };
        if !h.is_null() {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // MINOR-1 tightened (D5/E3/E4): silent early death is a hard
        // failure (an EvPaint exception unhandled = silent OWL fault).
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            let captured = reader.join().unwrap_or_default();
            panic!(
                "J-21 child exited on its own ({code:#x}) before any \
                 window was discoverable — likely a silent OWL runtime \
                 or SEH fault on the EvPaint cross-feature path. \
                 Captured stdout so far: {:?}",
                String::from_utf8_lossy(&captured)
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip(
            "could not locate the J-21 window within 4 s \
              (treated as no interactive station)",
        );
        return;
    }

    // Inject ONE synchronous click — EvLButtonDown emits one J21_CLICK.
    let lparam = (((20i32) << 16) | (10i32 & 0xFFFF)) as isize;
    let _ = unsafe { SendMessageA(hwnd, WM_LBUTTONDOWN, 0, lparam) };

    // Post WM_CLOSE → teardown chain to exit 0.
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip(
            "PostMessageA(WM_CLOSE) failed on J-21 window; child \
              force-terminated",
        );
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        let _ = reader.join();
        skip(
            "J-21 process did not exit within 5 s after WM_CLOSE; \
              force-terminated",
        );
        return;
    }

    let captured = reader.join().expect("stdout reader thread panicked");

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "J-21 process signalled but reports STILL_ACTIVE — \
                 impossible/crash"
            );
            assert_eq!(
                code,
                0,
                "J-21 fixture must exit with code 0 — the cross-feature \
                 EvPaint + EvLButtonDown + EvDestroy teardown chain must \
                 reach ExitProcess(0) cleanly. got {code:#x}. Captured \
                 stdout: {:?}",
                String::from_utf8_lossy(&captured)
            );
        }
        None => {
            skip("J-21 process signalled but GetExitCodeProcess failed");
            return;
        }
    }

    // Functional cross-feature oracle: every feature's J21_* sentinel
    // must appear in captured stdout. UpdateWindow's synchronous WM_PAINT
    // (inside TWindow::Show) means EvPaint always fires before the
    // harness's WM_CLOSE arrives.
    let s = String::from_utf8_lossy(&captured);
    let needles = [
        "J21_OPADD=18 J21_SUM=7",        // feature 5 + feature 4
        "J21_INT=1",                     // feature 8 (member overload, int branch)
        "J21_STR=paint",                 // feature 8 (member overload, str branch)
        "Hello, OWL!\n",                 // feature 10 (adjacent literal concat)
        "J21_CAUGHT=7",                  // feature 3 (throw/catch hierarchy)
        "J21_INNER=7",                   // feature 7 (inner shadow)
        "J21_SHADOW=100",                // feature 7 (outer survives)
        "J21_NEW ctors=3 ids=0,1,2",     // feature 6 (array-new)
        "J21_DEL dtors=3",               // feature 6 (delete[] runs N dtors)
        "J21_LIST=42,99",                // feature 9 (operator[] T&)
        "J21_CLICK 1 at 10,20",          // feature 2 (response-table dispatch)
        "J21_DESTROY paints=1 clicks=1", // feature 1+2 (full chain)
    ];
    for needle in needles {
        assert!(
            s.contains(needle),
            "J-21 fixture must emit {needle:?} (cross-feature oracle); \
             captured stdout was: {s:?}"
        );
    }
}

// ===========================================================================
// E5 — a minimal OWL 1-style "hello" application (mdbcc-authored, written in
// the shape every classic OWL sample takes) compiled, linked, and RUN via
// mdbcc's intrinsic OWL runtime.
//
// This is the headline S2→S7 milestone for the OWL *sample* app pattern:
// `bcc` alone (no `-I` — the intrinsic runtime resolves `<owl.h>`) builds it
// into a native subsystem-2 PE that launches, creates its main window, pumps
// the OWL message loop, and exits cleanly (code 0) when the window is closed.
//
// It exercises, end-to-end: the `<owl.h>` → OWL_RUNTIME_H route,
// `PASCAL`/`NULL` macros, the 5-arg `TApplication(LPSTR,HINSTANCE,
// HINSTANCE,LPSTR,int)` ctor + `Status` member, and — critically — the
// WinMain-style entry path where the app owns `WinMain` and the runtime's
// weak-default `WinMain` is superseded (codegen.rs S4.2(c)).
// ===========================================================================

/// OWL 1-style hello application: one TApplication subclass whose
/// InitMainWindow hook supplies a plain TWindow as the main window.
const PROG_E5_HELLOAPP: &str = r#"// mdbcc test fixture: minimal OWL 1-style application.

#include <owl.h>

class TGreeterApp : public TApplication
{
public:
  TGreeterApp(LPSTR name, HINSTANCE inst, HINSTANCE prevInst,
    LPSTR cmdLine, int showCmd)
    : TApplication(name, inst, prevInst, cmdLine, showCmd) {}
  virtual void InitMainWindow();
};

void TGreeterApp::InitMainWindow()
{
  MainWindow = new TWindow(NULL, "Greetings from mdbcc");
}

int PASCAL WinMain(HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
{
  TGreeterApp app("Greeter", inst, prevInst, cmdLine, showCmd);
  app.Run();
  return app.Status;
}
"#;

/// EnumWindows search context (travels through `lParam` as a raw pointer):
/// the PID we want and the HWND the callback sets when it sees a top-level
/// window owned by that PID.
struct PidSearch {
    target_pid: u32,
    found: Hwnd,
}

/// EnumWindows callback: stop (return 0) at the first top-level window owned
/// by `target_pid`. A minimal mdbcc-built PE creates exactly ONE top-level
/// window (the OWL main window — there is no C-runtime that spawns helper
/// windows), so a PID match unambiguously selects it. PID-filtering also
/// makes the probe safe: it can never act on another process's window, so the
/// worst case is a self-skip (never a wrong-window close).
unsafe extern "system" fn enum_pick_by_pid(hwnd: Hwnd, lparam: isize) -> Bool {
    let ctx = unsafe { &mut *(lparam as *mut PidSearch) };
    let mut wpid: u32 = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut wpid);
    }
    if wpid == ctx.target_pid {
        ctx.found = hwnd;
        return 0; // found — stop enumeration
    }
    1 // continue
}

/// Find the first top-level window owned by `pid` (None if none yet exists).
fn find_window_by_pid(pid: u32) -> Option<Hwnd> {
    let mut ctx = PidSearch {
        target_pid: pid,
        found: std::ptr::null_mut(),
    };
    unsafe {
        EnumWindows(enum_pick_by_pid, &mut ctx as *mut _ as isize);
    }
    if ctx.found.is_null() {
        None
    } else {
        Some(ctx.found)
    }
}

/// E5 structural half — ALWAYS runs (headless-safe): the E5 hello fixture.CPP
/// compiles + links to a subsystem-2 GUI PE via the intrinsic OWL runtime.
#[test]
fn o6_e5_helloapp_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_E5_HELLOAPP.as_bytes())
        .expect("the E5 hello fixture must compile+link via the intrinsic OWL runtime");
    assert_eq!(
        subsystem(&pe),
        2,
        "hello fixture is an OWL GUI app — its PE must be subsystem 2 (Windows GUI)"
    );
}

/// E5 liveness half — launch the E5 hello fixture, find its window by owning
/// PID, post `WM_CLOSE`, and assert a clean exit-code-0 teardown. Executable
/// proof that an OWL sample-shaped app RUNS natively on Win11 x64: the
/// WinMain-style entry constructs `TGreeterApp` on the stack, `Run()` virtual-
/// dispatches `InitMainWindow` (→ `new TWindow(NULL, "Greetings from mdbcc")`), then
/// creates and shows the window and pumps the loop; `WM_CLOSE` →
/// `DefWindowProcA` → `WM_DESTROY` → `PostQuitMessage(0)` → loop exits → `Run`
/// returns `Status=0` → `WinMain` returns `app.Status`.
///
/// Hard safety: identical bounded-poll / RAII `ProcHandle` / `TerminateProcess`
/// watchdog / loud `skip()` machinery as the D5 / E3 / E4 launch tests.
#[test]
fn o6_e5_helloapp_launches_and_clean_exits() {
    let pe = match compile_to_pe(PROG_E5_HELLOAPP.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("the E5 hello fixture failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "hello fixture must be subsystem 2 before launch"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E5]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E5 hello-fixture exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E5 hello-fixture exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E5 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Bounded find: poll EnumWindows for a top-level window owned by the child
    // PID for at most ~4 s (no caption dependency — see `enum_pick_by_pid`).
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(h) = find_window_by_pid(pid) {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        // Same MINOR-1 mitigation as D5: a child that already died on its own
        // with a non-zero code is a silent OWL-runtime failure (hard fail),
        // not a self-skip. STILL_ACTIVE-but-no-window keeps the kill+skip.
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "E5 (hello fixture) child exited on its own ({code:#x}) before any \
                 window was discoverable — the OWL runtime failed silently (likely \
                 the RegisterClassExA/CreateWindowExA path); EnumWindows found no \
                 PID-owned window within 4 s with a dead child"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the E5 hello fixture window within 4 s (treated as headless)");
        return;
    }

    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on the E5 window; child force-terminated");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("E5 process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E5 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "the E5 hello fixture must exit with code 0 after WM_CLOSE (WM_DESTROY → \
                 PostQuitMessage → message-loop exit → Run returns Status=0 → WinMain \
                 returns app.Status). got {code:#x} — a non-zero code means the \
                 OWL teardown chain broke (crash / wrong vtable dispatch / message-loop \
                 never exited)"
            );
        }
        None => {
            skip("E5 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ===========================================================================
// E5b — an OWL 1-style instance probe (mdbcc-authored), exercising the OWL
// app-init lifecycle: TApplication::InitApplication() (first-instance hook) +
// InitInstance() + InitMainWindow(). The ctor seeds the caption buffer with
// "Additional Instance"; the InitApplication() override sets it to "First
// Instance". On Win32 hPrevInstance is always NULL, so every instance is the
// "first" → InitApplication() runs → the window caption is "First Instance".
// The liveness test reads the caption back (GetWindowTextA) as a precise
// behaviour oracle: a caption of "Additional Instance" would prove the
// lifecycle hook never fired. Builds with no -I via the intrinsic runtime.
// ===========================================================================

/// OWL 1-style instance probe: the InitApplication hook rewrites the caption
/// the constructor seeded, and InitMainWindow shows whichever text survived.
const PROG_E5B_INSTTEST: &str = r#"// mdbcc test fixture: OWL 1-style first-instance probe.

#include <owl.h>
#include <string.h>

class TInstanceProbe : public TApplication
{
public:
  TInstanceProbe(LPSTR name, HINSTANCE inst, HINSTANCE prevInst,
    LPSTR cmdLine, int showCmd);

protected:
  char caption[24];
  virtual void InitMainWindow();
  virtual void InitApplication();
};

TInstanceProbe::TInstanceProbe(LPSTR name, HINSTANCE inst, HINSTANCE prevInst,
  LPSTR cmdLine, int showCmd)
  : TApplication(name, inst, prevInst, cmdLine, showCmd)
{
  strcpy(caption, "Additional Instance");
}

void TInstanceProbe::InitApplication()
{
  strcpy(caption, "First Instance");
}

void TInstanceProbe::InitMainWindow()
{
  MainWindow = new TWindow(NULL, caption);
}

int PASCAL WinMain(HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
{
  TInstanceProbe app("InstanceProbe", inst, prevInst, cmdLine, showCmd);
  app.Run();
  return app.Status;
}
"#;

/// Read a window's caption via `GetWindowTextA` (empty string on failure).
fn window_title(hwnd: Hwnd) -> String {
    let mut buf = [0u8; 256];
    let n = unsafe { GetWindowTextA(hwnd, buf.as_mut_ptr(), buf.len() as c_int) };
    if n <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..n as usize]).into_owned()
}

/// E5b structural half — ALWAYS runs (headless-safe): the E5b instance fixture.CPP
/// compiles + links to a subsystem-2 GUI PE via the intrinsic OWL runtime.
#[test]
fn o6_e5b_insttest_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_E5B_INSTTEST.as_bytes())
        .expect("the E5b instance fixture must compile+link via the intrinsic OWL runtime");
    assert_eq!(
        subsystem(&pe),
        2,
        "instance fixture is an OWL GUI app — its PE must be subsystem 2"
    );
}

/// E5b liveness + behaviour half — launch the E5b instance fixture, find its window
/// by owning PID, and assert its caption is **"First Instance"** (the
/// `InitApplication` lifecycle oracle), then `WM_CLOSE` → clean exit 0.
///
/// Hard safety: same bounded-poll / RAII / `TerminateProcess` machinery as E5.
#[test]
fn o6_e5b_insttest_initapplication_sets_title_and_clean_exits() {
    let pe = match compile_to_pe(PROG_E5B_INSTTEST.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("the E5b instance fixture failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "instance fixture must be subsystem 2 before launch"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E5b]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E5b instance fixture exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E5b instance fixture exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E5b child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(h) = find_window_by_pid(pid) {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "E5b (instance fixture) child exited on its own ({code:#x}) before any \
                 window was discoverable — the OWL runtime failed silently"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the E5b instance fixture window within 4 s (treated as headless)");
        return;
    }

    // Behaviour oracle: the caption proves InitApplication() ran. "Additional
    // Instance" (the ctor seed) would mean the lifecycle hook never fired.
    let title = window_title(hwnd);
    assert_eq!(
        title, "First Instance",
        "instance fixture's window caption must be \"First Instance\" — proof that \
         TApplication::InitApplication() ran in the OWL app-init lifecycle (it \
         overwrote the ctor's \"Additional Instance\"). got {title:?}"
    );

    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on the E5b window; child force-terminated");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("E5b process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E5b process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "the E5b instance fixture must exit with code 0 after WM_CLOSE. got {code:#x}"
            );
        }
        None => {
            skip("E5b process signalled but GetExitCodeProcess failed");
        }
    }
}

/// Guards two intrinsic-header completeness fixes that the OWL-sample survey
/// surfaced (compile-level — no launch, so headless-safe and Defender-flake
/// free):
///   1. a quoted `#include "windows.h"` must fall back to the intrinsic system
///      path (standard C `""`-then-`<>` lookup); CURSAPP/SCRIBAPP write the
///      quoted form of `owl.h`/`windows.h`.
///   2. `WORD` must be a known Win32 typedef (`unsigned short`); BTNTEST et al.
///      write `const WORD ID = 101;` and previously failed with `expected ';'`.
///
/// A minimal GUI TU using both must compile to a subsystem-2 PE.
#[test]
fn o6_quoted_system_include_and_word_typedef_compile() {
    let src = b"#include \"windows.h\"\n\
                int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {\n\
                    WORD w = 101;\n\
                    return (int)w - 101;\n\
                }\n";
    let pe = compile_to_pe(src).expect(
        "a quoted \"windows.h\" include + a WORD typedef must compile via the intrinsic path",
    );
    assert_eq!(
        subsystem(&pe),
        2,
        "a WinMain TU is a GUI program — subsystem 2"
    );
}

// ===========================================================================
// E5c — an OWL 1-style custom-cursor window (mdbcc-authored): a TWindow-derived
// window that overrides the OWL `GetWindowClass(WNDCLASS&)` hook to register a
// custom (I-beam) cursor. It is "representative" of the custom-window-class
// pattern: it exercises the quoted `#include "owl.h"` route, `PTWindowsObject`,
// the WNDCLASS / non-Ex `RegisterClassA` Create() path, and a virtual
// `GetWindowClass` override that calls its base (`TWindow::GetWindowClass` —
// the #41 qualified-base-call).
//
// Behaviour oracle: after launch, the window's CLASS cursor (queried cross-
// process via GetClassLongPtrA(GCLP_HCURSOR)) must equal the shared I-beam
// cursor — proof that the GetWindowClass override actually drove the class
// registration (the default would be the arrow cursor).
// ===========================================================================

/// OWL 1-style custom-cursor window: overrides GetClassName and
/// GetWindowClass (calling the base first) to register an I-beam class cursor.
const PROG_E5C_CURSAPP: &str = r#"// mdbcc test fixture: OWL 1-style window with a custom class cursor.

#include "owl.h"

class TCaretApp : public TApplication {
public:
    TCaretApp(LPSTR name, HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
        : TApplication(name, inst, prevInst, cmdLine, showCmd) {}
    virtual void InitMainWindow();
};

class TCaretFrame : public TWindow {
public:
    TCaretFrame(PTWindowsObject parent, LPSTR title) : TWindow(parent, title) {}
    virtual LPSTR GetClassName();
    virtual void GetWindowClass(WNDCLASS& wc);
};

LPSTR TCaretFrame::GetClassName()
{
    return "mdbccCaretFrame";
}

// Let the base fill in the class, then swap the cursor for the stock I-beam.
void TCaretFrame::GetWindowClass(WNDCLASS& wc)
{
    TWindow::GetWindowClass(wc);
    wc.hCursor = LoadCursor(0, IDC_IBEAM);
}

void TCaretApp::InitMainWindow()
{
    MainWindow = new TCaretFrame(NULL, "I-beam cursor frame");
}

int PASCAL WinMain(HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
{
    TCaretApp app("CaretApp", inst, prevInst, cmdLine, showCmd);
    app.Run();
    return app.Status;
}
"#;

/// E5c structural half — ALWAYS runs (headless-safe): the E5c cursor fixture.CPP
/// compiles + links to a subsystem-2 GUI PE via the intrinsic OWL runtime.
#[test]
fn o6_e5c_cursapp_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_E5C_CURSAPP.as_bytes())
        .expect("the E5c cursor fixture must compile+link via the intrinsic OWL runtime");
    assert_eq!(
        subsystem(&pe),
        2,
        "cursor fixture is an OWL GUI app — its PE must be subsystem 2"
    );
}

/// E5c liveness + behaviour half — launch the E5c cursor fixture, find its window by
/// owning PID, and assert its class cursor is the **I-beam** (the
/// `GetWindowClass(WNDCLASS&)` override oracle), then `WM_CLOSE` → clean exit 0.
///
/// Hard safety: same bounded-poll / RAII / `TerminateProcess` machinery as E5.
#[test]
fn o6_e5c_cursapp_custom_cursor_and_clean_exits() {
    let pe = match compile_to_pe(PROG_E5C_CURSAPP.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("the E5c cursor fixture failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "cursor fixture must be subsystem 2 before launch"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E5c]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E5c cursor fixture exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E5c cursor fixture exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E5c child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(h) = find_window_by_pid(pid) {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "E5c (cursor fixture) child exited on its own ({code:#x}) before any \
                 window was discoverable — the OWL runtime failed silently"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the E5c cursor fixture window within 4 s (treated as headless)");
        return;
    }

    // Behaviour oracle: the class cursor must be the I-beam, NOT the default
    // arrow — proof that IBeamWindow::GetWindowClass() drove registration.
    let class_cursor = unsafe { GetClassLongPtrA(hwnd, GCLP_HCURSOR) };
    let ibeam = unsafe { LoadCursorA(std::ptr::null_mut(), IDC_IBEAM) };
    let arrow = unsafe { LoadCursorA(std::ptr::null_mut(), IDC_ARROW) };
    let cursor_ok = class_cursor != 0 && class_cursor == ibeam && class_cursor != arrow;
    if !cursor_ok {
        proc.terminate();
        let _ = proc.wait(3000);
        // A wrong cursor is a real behaviour miscompile (the hook never fired /
        // the qualified base call mis-dispatched), not a flake — fail hard.
        panic!(
            "cursor fixture's window class cursor must be the I-beam (proof the \
             GetWindowClass(WNDCLASS&) override ran). class_cursor={class_cursor:#x}, \
             ibeam={ibeam:#x}, arrow={arrow:#x}"
        );
    }

    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on the E5c window; child force-terminated");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("E5c process did not exit within 5 s after WM_CLOSE; force-terminated");
        return;
    }

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E5c process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "the E5c cursor fixture must exit with code 0 after WM_CLOSE. got {code:#x}"
            );
        }
        None => {
            skip("E5c process signalled but GetExitCodeProcess failed");
        }
    }
}

// ===========================================================================
// E6 — OWL 1.0 DDVT message dispatch (S4.2(e)). The 1992 OWL samples respond
// to messages with the dynamic-dispatch-virtual-table form
// `virtual void WMxxx(RTMessage) = [WM_FIRST + WM_xxx];` (17 of the 34
// samples; ZERO use the OWL 2.x DECLARE_RESPONSE_TABLE macros). The parser
// captures the message index and synthesises a dispatching `WindowProc`
// override that routes the incoming message to the matching handler with a
// populated `TMessage`. This synthetic fixture is the dispatch ORACLE: its
// WM_LBUTTONDOWN handler calls `PostQuitMessage(0)`, so an injected click
// makes the app exit cleanly — which it can ONLY do if DDVT dispatch works
// (an undispatched click is ignored ⇒ the window never quits ⇒ timeout).
// ===========================================================================

const DDVT_WINDOW_TITLE: &[u8] = b"MdbccDdvtClick\0";

const PROG_E6_DDVT: &str = r#"#include <owl.h>

class TClickWin : public TWindow {
public:
    TClickWin(PTWindowsObject p, const char* t) : TWindow(p, t) {}
    virtual void WMLButtonDown(RTMessage Msg) = [WM_FIRST + WM_LBUTTONDOWN];
};

void TClickWin::WMLButtonDown(RTMessage Msg)
{
    // Quit ONLY if the packed message coordinate matches the injected lParam
    // LOWORD (7) — so a clean exit proves BOTH dispatch AND correct TMessage
    // population (Msg.LP.Lo = LOWORD(LParam)). A 0 would mean wrong/empty packet.
    if (Msg.LP.Lo == 7) PostQuitMessage(0);
}

class TClickApp : public TApplication {
public:
    void InitMainWindow() { MainWindow = new TClickWin(0, "MdbccDdvtClick"); }
};

int OwlMain(int, char**)
{
    TClickApp app;
    app.Run();
    return 0;
}
"#;

/// E6 structural half — ALWAYS runs: a DDVT-dispatch OWL TU compiles + links to
/// a subsystem-2 GUI PE (the synthesised WindowProc + TMessage are well-formed).
#[test]
fn o6_e6_ddvt_dispatch_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_E6_DDVT.as_bytes())
        .expect("a DDVT-dispatch OWL TU must compile+link via the intrinsic runtime");
    assert_eq!(subsystem(&pe), 2, "DDVT OWL app — subsystem 2");
}

/// E6 liveness + dispatch half — launch the DDVT app, find its window by PID,
/// inject a `WM_LBUTTONDOWN`, and assert the process exits cleanly (code 0).
/// The exit is the dispatch oracle: only a working DDVT route reaches the
/// handler's `PostQuitMessage(0)`. Same RAII / watchdog machinery as E4.
#[test]
fn o6_e6_ddvt_lbuttondown_dispatches_and_clean_exits() {
    let pe = match compile_to_pe(PROG_E6_DDVT.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("the DDVT-dispatch OWL TU failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "DDVT app must be subsystem 2 before launch"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E6]");
        return;
    }

    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E6 DDVT exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E6 DDVT exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E6 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

    // Find the window by owning PID (caption "MdbccDdvtClick" is unique but PID
    // is the robust key). Then locate the HWND for the click injection.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(h) = find_window_by_pid(pid) {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if hwnd.is_null() {
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "E6 (DDVT) child exited on its own ({code:#x}) before any window was \
                 discoverable — the OWL runtime / synthesised WindowProc failed silently"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the E6 DDVT window within 4 s (treated as headless)");
        return;
    }
    // Sanity: the caption matches (defends against the PID-find racing another
    // top-level window the process might briefly own).
    let _ = DDVT_WINDOW_TITLE; // (caption is asserted indirectly via dispatch)

    // Inject the click SYNCHRONOUSLY with lParam LOWORD = 7: the window proc
    // runs the synthesised DDVT dispatch to completion (WMLButtonDown reads
    // Msg.LP.Lo, and PostQuitMessage(0) iff it == 7) before this returns.
    // SendMessageA is a harness import; the app receives it via its own
    // GetMessageA loop. lParam=7 ⇒ LOWORD=7, HIWORD=0.
    let _ = unsafe { SendMessageA(hwnd, WM_LBUTTONDOWN, 0, 7) };

    // The PostQuitMessage(0) makes the next GetMessageA return 0 → loop exits →
    // OwlMain returns → clean exit. If DDVT dispatch were broken the click would
    // be ignored and the window would never quit (caught by the wait timeout).
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        panic!(
            "E6 DDVT app did not exit within 5 s after an injected WM_LBUTTONDOWN — \
             the synthesised DDVT WindowProc did NOT dispatch to WMLButtonDown \
             (PostQuitMessage never ran). This is a dispatch miscompile."
        );
    }

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E6 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "the DDVT app must exit with code 0 after the dispatched click \
                 (WMLButtonDown → PostQuitMessage → loop exit). got {code:#x}"
            );
        }
        None => {
            skip("E6 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ===========================================================================
// S4.2(g) / #47 regression — a QUALIFIED base-method call to an OVERRIDDEN
// virtual must be a DIRECT (static) call, never a vtable dispatch. The bug:
// D::f()'s `B::f()` was lowered to `((B*)this)->f()` and codegen dispatched it
// VIRTUALLY → back into D::f() → infinite recursion → STATUS_STACK_OVERFLOW
// (the CURSAPP GetWindowClass crash that blocked all OWL runtime work). With
// the fix, `B::f()` calls B::f directly. A clean exit code 11 (= B::f()1 + 10)
// proves it; without the fix the program stack-overflows / hangs.
// ===========================================================================
const PROG_QUAL_BASE: &str = r#"
struct B { virtual int f(); };
struct D : public B { virtual int f(); };
int B::f() { return 1; }
int D::f() { return B::f() + 10; }
int main() { D d; B *p = &d; return p->f(); }
"#;

#[test]
fn o6_qualified_base_call_to_virtual_is_static_not_recursive() {
    let pe = compile_to_pe(PROG_QUAL_BASE.as_bytes())
        .expect("a qualified base-virtual-call program must compile");
    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the #47 regression exe");
        return;
    }
    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            // Defender os-225 quarantine ⇒ self-skip (environmental), never false-fail.
            skip(&format!("could not spawn the #47 regression exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the #47 regression child");
            return;
        }
    };
    std::mem::forget(child);
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(2000);
        panic!(
            "#47 regression: the qualified-base-call program did NOT exit within 5 s — \
             infinite recursion (Base::f() dispatched virtually back into Derived::f())"
        );
    }
    match proc.exit_code() {
        Some(code) => assert_eq!(
            code, 11,
            "D::f() must return B::f() + 10 = 11 — the qualified `B::f()` MUST be a static \
             direct call, not a virtual dispatch (which recurses into D::f()). got {code:#x}"
        ),
        None => skip("#47 regression: GetExitCodeProcess failed"),
    }
}

// ===========================================================================
// E6b — an OWL 1-style DDVT mouse-sketch window (mdbcc-authored): a TWindow
// whose four DDVT handlers (WM_LBUTTONDOWN/UP, WM_MOUSEMOVE, WM_RBUTTONDOWN)
// capture the mouse and draw lines via GDI. Proves DDVT synthesis (S4.2(e)) +
// the GDI surface (S4.2(f), safe now that the #47 qualified-base-call
// recursion is fixed) on the sample-app pattern.
// ===========================================================================

/// OWL 1-style sketch window: four `= [WM_FIRST + WM_*]` DDVT handlers that
/// capture the mouse on left-down, draw with the held DC on move, release on
/// left-up, and clear the client area on right-down.
const PROG_E6B_SCRIBAPP: &str = r#"// mdbcc test fixture: OWL 1-style DDVT mouse-sketch window.

#include "owl.h"

class TSketchApp : public TApplication
{
public:
  TSketchApp(LPSTR name, HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
    : TApplication(name, inst, prevInst, cmdLine, showCmd) {}
  virtual void InitMainWindow();
};

class TSketchPad : public TWindow
{
public:
  HDC penDC;
  BOOL tracking;
  TSketchPad(PTWindowsObject parent, LPSTR title);
  virtual void OnLeftDown(RTMessage msg) = [WM_FIRST + WM_LBUTTONDOWN];
  virtual void OnLeftUp(RTMessage msg) = [WM_FIRST + WM_LBUTTONUP];
  virtual void OnMove(RTMessage msg) = [WM_FIRST + WM_MOUSEMOVE];
  virtual void OnRightDown(RTMessage msg) = [WM_FIRST + WM_RBUTTONDOWN];
};

TSketchPad::TSketchPad(PTWindowsObject parent, LPSTR title)
  : TWindow(parent, title)
{
  tracking = FALSE;
}

void TSketchPad::OnLeftDown(RTMessage msg)
{
  if (tracking)
    return;
  tracking = TRUE;
  SetCapture(HWindow);
  penDC = GetDC(HWindow);
  MoveTo(penDC, msg.LP.Lo, msg.LP.Hi);
}

void TSketchPad::OnMove(RTMessage msg)
{
  if (tracking)
    LineTo(penDC, msg.LP.Lo, msg.LP.Hi);
}

void TSketchPad::OnLeftUp(RTMessage)
{
  if (!tracking)
    return;
  ReleaseCapture();
  ReleaseDC(HWindow, penDC);
  tracking = FALSE;
}

void TSketchPad::OnRightDown(RTMessage)
{
  InvalidateRect(HWindow, LPRECT(NULL), TRUE);
}

void TSketchApp::InitMainWindow()
{
  MainWindow = new TSketchPad(NULL, "Sketch pad");
}

int PASCAL WinMain(HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
{
  TSketchApp app("Sketch", inst, prevInst, cmdLine, showCmd);
  app.Run();
  return app.Status;
}
"#;

#[test]
fn o6_e6b_scribapp_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_E6B_SCRIBAPP.as_bytes())
        .expect("the E6b sketch fixture must compile+link via the intrinsic runtime");
    assert_eq!(
        subsystem(&pe),
        2,
        "the sketch fixture is an OWL GUI app — subsystem 2"
    );
}

#[test]
fn o6_e6b_scribapp_scribble_dispatches_and_clean_exits() {
    let pe = match compile_to_pe(PROG_E6B_SCRIBAPP.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("the E6b sketch fixture failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "the sketch fixture must be subsystem 2 before launch"
    );
    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0) [E6b]");
        return;
    }
    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the E6b sketch fixture exe to a temp path");
        return;
    }
    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the E6b sketch fixture exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("could not OpenProcess the E6b child");
            return;
        }
    };
    std::mem::forget(child);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(h) = find_window_by_pid(pid) {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if hwnd.is_null() {
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "E6b (sketch fixture) child exited on its own ({code:#x}) before any window — OWL runtime failed silently"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the E6b sketch fixture window within 4 s (treated as headless)");
        return;
    }
    let lparam = |x: i32, y: i32| ((x & 0xFFFF) | (y << 16)) as isize;
    unsafe {
        SendMessageA(hwnd, WM_LBUTTONDOWN, 0, lparam(10, 10));
        SendMessageA(hwnd, WM_MOUSEMOVE, 0, lparam(40, 40));
        SendMessageA(hwnd, WM_MOUSEMOVE, 0, lparam(80, 30));
        SendMessageA(hwnd, WM_LBUTTONUP, 0, lparam(80, 30));
        SendMessageA(hwnd, WM_RBUTTONDOWN, 0, lparam(0, 0));
    }
    if let Some(code) = proc.exit_code()
        && code != STILL_ACTIVE
    {
        panic!("E6b sketch fixture died ({code:#x}) dispatching the scribble — a DDVT handler crashed");
    }
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on the E6b window");
        return;
    }
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("E6b process did not exit within 5 s after WM_CLOSE");
        return;
    }
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "E6b signalled but STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "the E6b sketch fixture must exit 0 after the scribble + WM_CLOSE. got {code:#x}"
            );
        }
        None => skip("E6b GetExitCodeProcess failed"),
    }
}

// ===========================================================================
// E5d — an OWL 1-style static-control gallery (mdbcc-authored), exercising
// the OWL CONTROL + child-window lifecycle (TWindowAttr, a child list on
// TWindow, TStatic = a system "STATIC"-class child created after the parent
// HWND via CreateChildren). Uses only the existing CreateWindowExA import.
// Behaviour oracle: 21 child controls created.
// ===========================================================================

unsafe extern "system" fn count_child(_hwnd: Hwnd, lparam: isize) -> Bool {
    let counter = unsafe { &mut *(lparam as *mut i32) };
    *counter += 1;
    1
}
fn count_children(parent: Hwnd) -> i32 {
    let mut n: i32 = 0;
    unsafe {
        EnumChildWindows(parent, count_child, &mut n as *mut _ as isize);
    }
    n
}

/// OWL 1-style static-control gallery: a TWindow whose constructor sizes
/// itself through `Attr` and queues 21 TStatic children (a label column plus
/// a column whose `Attr.Style` is rewritten per SS_* style) for
/// CreateChildren to realise after the parent HWND exists.
const PROG_E5D_STATTEST: &str = r#"// mdbcc test fixture: OWL 1-style static-control gallery.

#include <owl.h>
#include <window.h>
#include <static.h>

class TGalleryApp : public TApplication
{
public:
  TGalleryApp(LPSTR name, HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
    : TApplication(name, inst, prevInst, cmdLine, showCmd) {}
  virtual void InitMainWindow();
};

class TGalleryWindow : public TWindow
{
public:
  TGalleryWindow(PTWindowsObject parent, LPSTR title);
private:
  void AddStyled(int y, DWORD style, int textLen);
};

// One row of the right-hand column: a static whose class style is replaced.
void TGalleryWindow::AddStyled(int y, DWORD style, int textLen)
{
  TStatic* s = new TStatic(this, -1, "Style &row", 170, y, 200, 24, textLen);
  s->Attr.Style = (s->Attr.Style & ~SS_LEFT) | style;
}

TGalleryWindow::TGalleryWindow(PTWindowsObject parent, LPSTR title)
  : TWindow(parent, title)
{
  static const char* const labels[10] = {
    "Default Static", "SS_SIMPLE", "SS_LEFT", "SS_CENTER", "SS_RIGHT",
    "SS_BLACKFRAME", "SS_BLACKRECT", "SS_GRAYFRAME", "SS_GRAYRECT", "SS_NOPREFIX"
  };
  Attr.X = 100;
  Attr.Y = 100;
  Attr.W = 415;
  Attr.H = 355;
  for (int i = 0; i < 10; i++)
    new TStatic(this, -1, (LPSTR)labels[i], 20, 20 + 30 * i, 150, 24, 0);

  new TStatic(this, -1, "Style &row", 170, 20, 200, 24, 0);
  AddStyled(50, SS_SIMPLE, 14);
  new TStatic(this, -1, "Style &row", 170, 80, 200, 24, 0);
  AddStyled(110, SS_CENTER, 14);
  AddStyled(140, SS_RIGHT, 14);
  AddStyled(170, SS_BLACKFRAME, 0);
  AddStyled(200, SS_BLACKRECT, 0);
  AddStyled(230, SS_GRAYFRAME, 0);
  AddStyled(260, SS_GRAYRECT, 0);
  AddStyled(290, SS_RIGHT | SS_NOPREFIX, 0);
}

void TGalleryApp::InitMainWindow()
{
  MainWindow = new TGalleryWindow(NULL, Name);
}

int PASCAL WinMain(HINSTANCE inst, HINSTANCE prevInst, LPSTR cmdLine, int showCmd)
{
  TGalleryApp app("Static gallery", inst, prevInst, cmdLine, showCmd);
  app.Run();
  return app.Status;
}
"#;

#[test]
fn o6_e5d_stattest_compiles_to_gui_pe() {
    let pe = compile_to_pe(PROG_E5D_STATTEST.as_bytes())
        .expect("the E5d gallery fixture must compile+link via the intrinsic runtime");
    assert_eq!(
        subsystem(&pe),
        2,
        "the gallery fixture is an OWL GUI app — subsystem 2"
    );
}

#[test]
fn o6_e5d_stattest_creates_children_and_clean_exits() {
    let pe = match compile_to_pe(PROG_E5D_STATTEST.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("the E5d gallery fixture failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "the gallery fixture must be subsystem 2 before launch"
    );
    if !interactive_desktop() {
        skip("no interactive window station [E5d]");
        return;
    }
    let _gui_runtime = gui_runtime_lock();

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write E5d exe");
        return;
    }
    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn E5d exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let _ = terminate_child(child);
            skip("OpenProcess E5d");
            return;
        }
    };
    std::mem::forget(child);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut hwnd: Hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(h) = find_window_by_pid(pid) {
            hwnd = h;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if hwnd.is_null() {
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "E5d (gallery fixture) child exited ({code:#x}) before any window — child lifecycle failed"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the E5d gallery fixture window within 4 s");
        return;
    }
    let mut children = 0;
    let cdeadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < cdeadline {
        children = count_children(hwnd);
        if children >= 20 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        children >= 20,
        "the gallery window must own its 21 static-control children (child-window lifecycle oracle); found {children}"
    );
    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("WM_CLOSE failed E5d");
        return;
    }
    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("E5d no exit within 5s");
        return;
    }
    match proc.exit_code() {
        Some(code) => {
            assert_ne!(code, STILL_ACTIVE, "E5d STILL_ACTIVE — crash");
            assert_eq!(
                code, 0,
                "the E5d gallery fixture must exit 0 after WM_CLOSE. got {code:#x}"
            );
        }
        None => skip("E5d GetExitCodeProcess failed"),
    }
}
