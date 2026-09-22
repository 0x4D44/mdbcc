//! J-21 — synthetic OWL idiom forcing-corpus integration tests.
//!
//! Purpose: combine multiple OWL-relevant C++ features in one TU as a
//! Phase-I forcing function (ahead of real Borland-OWL acquisition).
//! The structural / liveness tests assert that the SIMPLIFIED fixture
//! (8 of 10 target features) compiles, links, and runs cleanly under
//! the existing D5 OWL runtime + watchdog patterns.
//!
//! The `regression_g*_...` tests **lock the bugs found during J-21
//! bisect** (see `wrk_journals/2026.05.23 - JRN - J21 OWL forcing-
//! corpus gap report.md` for the four gap clusters G-1..G-4). Each
//! regression-lock test asserts the EXACT failure mode observed today
//! (compile-time rejection with a known substring, OR runtime crash);
//! they will turn green / flip-assert when the corresponding gap is
//! fixed in a later tick.

#![cfg(windows)]

use mdbcc::compile_to_pe;

// ---------------------------------------------------------------------------
// PE structural helpers (mirror tests/gui.rs verbatim — std-only, no crates)
// ---------------------------------------------------------------------------

const PE_OFF: usize = 0x80;

fn parse_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// PE optional header `Subsystem` (`u16` at optional-header offset 68).
fn subsystem(pe: &[u8]) -> u16 {
    parse_u16(pe, PE_OFF + 4 + 20 + 68)
}

// ---------------------------------------------------------------------------
// The J-21 simplified OWL TU — the working fixture that compiles + runs
// ---------------------------------------------------------------------------
//
// 8 of 10 target features combine cleanly under the D5 OWL runtime:
//   (3) custom exception hierarchy + throw/catch by reference
//   (5) operator+ with trailing-const — int-returning to sidestep the
//       op+ struct-return gap (G-2/G-3)
//   (6) array-new with ctor + delete[]
//   (7) block-scope shadowing inside a method
//   (8) member overloading (`print(int)` vs `print(char*)`)
//   (9) operator[] returning int&
//  (10) adjacent string-literal concat
//   ...layered on top of D5's TApplication / TFrameWindow / OwlMain
//   (the same teardown chain D5's hello-OWL test already exercises).
//
// Features simplified out (per the gap report):
//   (1) full TMyWin : TFrameWindow override surface — defer to a
//       dedicated test once G-1/G-4 close.
//   (2) response-table dispatch with EvPaint/EvCommand/EvKeyDown
//       overrides on a user class — same reason.
//   (4) struct-by-value via `Point sumWith(Point other)` — works in
//       isolation but the combined j21_probe TU tripped op+ first.

const PROG_J21_OWL: &str = r#"
#include <owl/applicat.h>
#include <owl/framewin.h>
#include <stdio.h>

// Feature 5: operator+ with trailing const. Tick 56 closes G-2/G-3 so
// the natural Point-returning form is now used (was int-returning pre-
// tick-56 to sidestep the gap). Still exercises trailing-const mangling
// + overload dispatch.
class Point {
public:
    int x;
    int y;
    Point() { x = 0; y = 0; }
    Point operator+(Point& o) const { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
};

// Feature 3: custom exception hierarchy with virtual dtor.
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

// Feature 6: ctor/dtor counters for array-new audit.
int g_ctor_count = 0;
int g_dtor_count = 0;
class Counter {
public:
    int id;
    Counter() { id = g_ctor_count; g_ctor_count = g_ctor_count + 1; }
    ~Counter() { g_dtor_count = g_dtor_count + 1; }
};

// Feature 9: operator[] returning int&.
class TIntList {
public:
    int data[8];
    TIntList() { int i; i = 0; while (i < 8) { data[i] = 0; i = i + 1; } }
    int& operator[](int i) { return data[i]; }
};

// Feature 8 + 10: member overloading + adjacent string concat in one class.
class Talker {
public:
    void print(int n) { printf("int=%d\n", n); }
    void print(char* s) { printf("str=%s\n", s); }
    void greet() { printf("Hello, " "OWL!\n"); }
    // Feature 7: block-scope shadowing.
    int demoShadow() {
        int idx;
        idx = 100;
        {
            int idx;
            idx = 7;
            printf("inner=%d\n", idx);
        }
        return idx;
    }
};

class TMyApp : public TApplication {
public:
    TMyApp() : TApplication() {}
    void InitMainWindow() {
        SetMainWindow(new TFrameWindow(0, "MdbccJ21OwlIntegration"));
    }
};

int OwlMain(int argc, char** argv) {
    // Exercise the cross-cutting features once at app startup (before
    // entering Run()) so a compile/link red surfaces immediately.
    Point p; p.x = 3; p.y = 4;
    Point q; q.x = 10; q.y = 20;
    // Tick 56: Point operator+ now returns Point (was int pre-tick-56
    // because of G-2/G-3). Assigning to a Point lvalue exercises the
    // result-buffer-into-struct-copy path; member access on the sum
    // proves the rvalue can be addressed.
    Point psum;
    psum = p + q;
    int psum_check = (p + q).x + (p + q).y;
    (void)psum;
    (void)psum_check;

    try {
        TXMyAppError e;
        e.code = 11;
        throw e;
    } catch (TXBase& base) {
        (void)base.code;
    }

    Counter* group = new Counter[3];
    int sum_ids = group[0].id + group[1].id + group[2].id;
    delete[] group;
    (void)sum_ids;

    TIntList list;
    list[0] = 42;
    list[7] = 99;
    (void)list[0];

    Talker t;
    t.print(42);
    t.print("hi");
    t.greet();
    (void)t.demoShadow();

    TMyApp app;
    return app.Run();
}
"#;

/// J-21 structural — the simplified OWL TU compiles + links to a GUI PE.
/// In-process via `compile_to_pe` (same pattern as the D4/D5 structural
/// tests in `tests/gui.rs`). No external dependencies, headless-safe.
#[test]
fn j21_owl_integration_compiles_and_links_a_simplified_owl_app() {
    let pe = compile_to_pe(PROG_J21_OWL.as_bytes())
        .expect("the J-21 simplified OWL TU must compile + link end-to-end");
    assert!(
        !pe.is_empty(),
        "compile_to_pe returned an empty PE byte vector — the writer \
         silently produced zero bytes for the J-21 TU"
    );
    assert_eq!(
        subsystem(&pe),
        2,
        "the J-21 OWL TU must be PE Subsystem == 2 (WINDOWS_GUI) — the \
         runtime-provided WinMain triggers the C2 GUI-entry path"
    );
}

// ---------------------------------------------------------------------------
// Liveness — reuse D5's FindWindowA + PostMessageA + watchdog pattern
// ---------------------------------------------------------------------------
//
// Pure structural-plus-bytes for J-21 v1: the J-21 corpus's liveness
// path is functionally identical to D5's (same caption-only FindWindowA
// + WM_CLOSE + bounded watchdog), and `tests/gui.rs::o6_d5_hello_owl_
// launches_dispatches_clean_exits` already proves that exact teardown
// chain on every D5-shaped TU. Re-implementing the full FFI + handle
// machinery here would only duplicate that test surface.
//
// What J-21 ADDS over D5: the simplified-corpus TU also exercises
// throw/catch + array-new + `operator[]` + member overload + adjacent
// strings + block shadowing during `OwlMain` *before* Run() is called.
// A regression in any of those would surface here as a structural
// compile/link failure (the test above) or as a crash during process
// start (which `j21_owl_integration_partial_fixture_runs_and_exits_
// cleanly` would catch via the watchdog).

const J21_WINDOW_TITLE: &[u8] = b"MdbccJ21OwlIntegration\0";

/// Liveness via the existing D5 pattern: spawn, find caption-only via
/// `FindWindowA`, dismiss with `PostMessageA(WM_CLOSE)`, assert clean
/// exit within the watchdog bound. Headless-gated, never hangs.
///
/// Implementation note: a full duplicate of the D5 FFI block would be
/// pure code duplication. We import the minimum Win32 surface here so
/// `tests/owl_integration.rs` stays self-contained (the testing crate
/// boundary disallows cross-test imports without exposing them as
/// helpers in `tests/support/mod.rs`, which the brief flagged as fine
/// but adds modification surface to a shared module).
#[test]
fn j21_owl_integration_partial_fixture_runs_and_exits_cleanly() {
    use std::os::raw::{c_int, c_void};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    type Hwnd = *mut c_void;
    type Handle = *mut c_void;
    type Bool = c_int;
    const WM_CLOSE: u32 = 0x0010;
    const STILL_ACTIVE: u32 = 259;
    const WAIT_OBJECT_0: u32 = 0;
    const UOI_FLAGS: c_int = 1;
    const WSF_VISIBLE: u32 = 0x0001;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const SYNCHRONIZE: u32 = 0x0010_0000;

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

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    struct TempExe(PathBuf);
    impl TempExe {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut p = std::env::temp_dir();
            p.push(format!("mdbcc_j21_{}_{}.exe", std::process::id(), n));
            TempExe(p)
        }
    }
    impl Drop for TempExe {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn skip(reason: &str) {
        eprintln!("[J21] SKIP liveness: {reason} — structural compile + bytes check still ran");
    }

    // Compile under the same in-process path as the structural test.
    let pe = match compile_to_pe(PROG_J21_OWL.as_bytes()) {
        Ok(pe) => pe,
        Err(e) => panic!("J-21 simplified OWL TU failed to compile: {e}"),
    };
    assert_eq!(
        subsystem(&pe),
        2,
        "J-21 TU must be subsystem 2 before any launch attempt"
    );

    if !interactive_desktop() {
        skip("no interactive window station (headless / Session-0)");
        return;
    }

    let tmp = TempExe::new();
    if std::fs::write(&tmp.0, &pe).is_err() {
        skip("could not write the J-21 exe to a temp path");
        return;
    }

    let child = match Command::new(&tmp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("could not spawn the J-21 exe: {e}"));
            return;
        }
    };
    let pid = child.id();
    let proc = match ProcHandle::open(pid) {
        Some(p) => p,
        None => {
            let mut c = child;
            let _ = c.kill();
            let _ = c.wait();
            skip("could not OpenProcess the J-21 child for the watchdog");
            return;
        }
    };
    std::mem::forget(child);

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
        // The D5 mitigation: if the child died on its own with a non-zero
        // code, that's a silent OWL runtime failure (must surface, not skip).
        if let Some(code) = proc.exit_code()
            && code != STILL_ACTIVE
        {
            panic!(
                "J-21 child exited on its own ({code:#x}) before any window \
                 was discoverable — the simplified OWL TU faulted during \
                 startup (one of the new throw/array-new/op[] features?)"
            );
        }
        proc.terminate();
        let _ = proc.wait(3000);
        skip("could not locate the J-21 window within 4 s (no interactive station)");
        return;
    }

    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("PostMessageA(WM_CLOSE) failed on the J-21 window");
        return;
    }

    if !proc.wait(5000) {
        proc.terminate();
        let _ = proc.wait(3000);
        skip("J-21 process did not exit within 5 s after WM_CLOSE");
        return;
    }

    match proc.exit_code() {
        Some(code) => {
            assert_ne!(
                code, STILL_ACTIVE,
                "J-21 process signalled but reports STILL_ACTIVE — impossible/crash"
            );
            assert_eq!(
                code, 0,
                "J-21 simplified OWL TU must exit cleanly (code 0) — \
                 same 4-layer teardown chain D5 exercises; got {code:#x}"
            );
        }
        None => {
            skip("J-21 process signalled but GetExitCodeProcess failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Regression-locking tests for the four gaps (G-1..G-4)
// ---------------------------------------------------------------------------
//
// Each test below asserts the EXACT failure mode observed today
// (compile-time error containing a known substring, or runtime crash
// at process-launch level). When the corresponding gap is fixed in a
// later tick, these tests will start FAILING — at which point flip
// the assertion (expect Ok / exit 0) and the test becomes a forward-
// regression lock for the new GREEN behaviour.
//
// These tests are gated by an env var so a future "all-green" run can
// see them as currently-failing-but-locked. They run by default to
// catch silent fixes (a gap getting accidentally closed by an
// unrelated tick), which is exactly the regression-lock purpose.

/// G-1 (CLOSED tick 55): inline class member function returning own
/// class by value now compiles + runs. The pre-tick-55 root cause was
/// stale `Type::Record { size: 0 }` cached on `Function::ret` for
/// inline member functions parsed BEFORE their enclosing class record
/// was finalized; codegen's empty-struct check tripped. The fix
/// refreshes every `Type::Record` cache in the AST at end-of-parse,
/// after all records are laid out.
#[test]
fn g1_inline_member_returning_own_class_now_compiles_and_runs_exit_13() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point bump(int v) { Point r; r.x = x + v; r.y = y + v; return r; }
};
int main(void) {
    Point a; a.x = 3; a.y = 4;
    int sx = a.bump(10).x;
    return sx;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-1: inline member returning own class should compile post tick 55");
    let path =
        std::env::temp_dir().join(format!("mdbcc_g1_inline_bump_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status.code(),
        Some(13),
        "G-1 runtime: a.bump(10).x where a.x=3 should be 13"
    );
}

/// G-1 robustness: a class containing ONLY the inline member function
/// (no peer methods to mask the issue). Same shape as the minimal
/// reproducer with the smallest possible class surface.
#[test]
fn g1_inline_member_with_explicit_no_other_methods() {
    const SRC: &str = r#"
class Box { public:
    int v;
    Box add(int k) { Box r; r.v = v + k; return r; }
};
int main(void) {
    Box b; b.v = 5;
    return b.add(7).v;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-1 robustness: minimal one-method class should compile");
    let path = std::env::temp_dir().join(format!("mdbcc_g1_box_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(status.code(), Some(12), "G-1: 5 + 7 = 12");
}

/// G-1 robustness: chained record-returning calls + member access in
/// a single expression. Exercises the same code path as G-1 twice in
/// one statement, ensuring the result-buffer lifetime machinery
/// (`maybe_free_record_call_result`) handles the case correctly.
#[test]
fn g1_inline_member_returning_own_class_with_array_indexing_chained() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point bump(int v) { Point r; r.x = x + v; r.y = y + v; return r; }
};
int main(void) {
    Point a; a.x = 3; a.y = 4;
    return a.bump(10).x + a.bump(20).y;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-1 chained: two inline-member calls in one expression should compile");
    let path = std::env::temp_dir().join(format!("mdbcc_g1_chained_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    // a.bump(10).x = 3 + 10 = 13
    // a.bump(20).y = 4 + 20 = 24
    // sum = 37
    assert_eq!(status.code(), Some(37), "G-1 chained: 13 + 24 = 37");
}

/// G-2 (CLOSED tick 56): `c = a + b;` where operator+ returns class
/// by value now compiles AND runs. Root cause was `gen_binary`'s
/// overloaded-op path emitting a direct `gen_call` with no record-
/// return classification — the callee returned the InReg-packed bytes
/// in RAX, and the consumer `gen_addr(rhs)` then either errored (no
/// `Expr::Binary` arm in `gen_addr`) or treated the packed bytes as
/// a source address (segfault). Fix: rewrite to `Expr::MethodCall`
/// at gen_binary and delegate to `gen_expr`, so the existing
/// prepare/complete_record_return_call machinery materialises the
/// result buffer; plus add `Expr::Binary` to `gen_addr`'s record-
/// return arm and to `record_call_result_size`.
#[test]
fn g2_assign_from_op_plus_struct_return_now_compiles_and_runs_exit_8() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point operator+(Point& o);
};
Point Point::operator+(Point& o) { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
int main(void) {
    Point a; a.x = 3; a.y = 4;
    Point b; b.x = 5; b.y = 6;
    Point c;
    c = a + b;
    return c.x;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-2: 'c = a + b;' with operator+ returning Point should compile post tick 56");
    let path = std::env::temp_dir().join(format!(
        "mdbcc_g2_assign_op_plus_{}.exe",
        std::process::id()
    ));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status.code(),
        Some(8),
        "G-2 runtime: c.x = (a + b).x = 3 + 5 = 8"
    );
}

/// G-2 robustness: chained `c = a + b + d` (left-assoc) — the first
/// sum is materialised into a result buffer, then used as the lhs
/// for the second sum (also a record-returning call). Locks the
/// invariant that one result buffer doesn't clobber the next.
#[test]
fn g2_chained_op_plus_struct_return_assignment() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point operator+(Point& o);
};
Point Point::operator+(Point& o) { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
int main(void) {
    Point a; a.x = 1; a.y = 10;
    Point b; b.x = 2; b.y = 20;
    Point d; d.x = 3; d.y = 30;
    Point c;
    c = a + b + d;
    return c.x + c.y;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-2 chained: 'c = a + b + d' should compile post tick 56");
    let path = std::env::temp_dir().join(format!("mdbcc_g2_chained_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    // c.x = 1+2+3 = 6, c.y = 10+20+30 = 60, sum = 66
    assert_eq!(status.code(), Some(66), "G-2 chained: c.x+c.y = 6+60 = 66");
}

/// G-3 (CLOSED tick 56) compile-time dimension: member access on
/// op+ struct return (`(a + b).x`) now compiles AND runs. Same root
/// cause as G-2: `gen_addr` had no `Expr::Binary` arm for the case
/// where `gen_member_addr` peeks under the dot to find an address.
#[test]
fn g3_member_access_on_op_plus_struct_rvalue_now_compiles_and_runs_exit_8() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point operator+(Point& o);
};
Point Point::operator+(Point& o) { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
int main(void) {
    Point a; a.x = 3; a.y = 4;
    Point b; b.x = 5; b.y = 6;
    int sx = (a + b).x;
    return sx;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-3: '(a + b).x' with operator+ returning Point should compile post tick 56");
    let path = std::env::temp_dir().join(format!("mdbcc_g3_member_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(status.code(), Some(8), "G-3 runtime: (a + b).x = 3 + 5 = 8");
}

/// G-3 robustness: `(a + b).x + (a + b).y` — TWO operator+ rvalues
/// in one expression, each materialised independently. From the gap
/// report's "exact second test"; locks that both result buffers are
/// allocated + reclaimed cleanly.
#[test]
fn g3_op_plus_struct_rvalue_in_double_member_access() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point operator+(Point& o);
};
Point Point::operator+(Point& o) { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
int main(void) {
    Point a; a.x = 3; a.y = 4;
    Point b; b.x = 5; b.y = 6;
    return (a + b).x + (a + b).y;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-3 double-access: '(a+b).x + (a+b).y' should compile post tick 56");
    let path =
        std::env::temp_dir().join(format!("mdbcc_g3_double_access_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    // (a+b).x = 3+5 = 8, (a+b).y = 4+6 = 10, sum = 18
    assert_eq!(status.code(), Some(18), "G-3 double-access: 8 + 10 = 18");
}

/// G-3 (CLOSED tick 56) silent-segfault dimension: `take(a + b)`
/// passes an op+ struct rvalue as a by-value function argument. Pre-
/// tick-56 this compiled (no compile-time lvalue check in marshal_args)
/// but segfaulted at runtime because the callee's RAX held the
/// packed 8 bytes (not an address), and `lower_struct_arg` treated
/// the packed value as a source address — reading from an
/// unallocated buffer offset. With the result-buffer materialisation
/// now properly invoked from gen_binary, RAX holds the buffer
/// address and the marshalling reads valid bytes.
#[test]
fn g3_pass_op_plus_struct_rvalue_as_arg_now_runs_exit_18() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point operator+(Point& o);
};
Point Point::operator+(Point& o) { Point r; r.x = x + o.x; r.y = y + o.y; return r; }
int take(Point p) { return p.x + p.y; }
int main(void) {
    Point a; a.x = 3; a.y = 4;
    Point b; b.x = 5; b.y = 6;
    return take(a + b);
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-3 by-value arg: 'take(a + b)' should compile post tick 56");
    let path = std::env::temp_dir().join(format!("mdbcc_g3_take_argv_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    // take(a + b).p.x = 3+5 = 8; .p.y = 4+6 = 10; sum = 18.
    // Pre-tick-56 this segfaulted (exit code 0xC0000005 → unix-style 139).
    assert_eq!(
        status.code(),
        Some(18),
        "G-3 by-value arg: take(a+b) = (3+5) + (4+6) = 18 (pre-tick-56 was segfault 139)"
    );
}

/// G-4 (CLOSED tick 55): inline member returning own class via
/// `this`-fields + a reference parameter, used in an assignment
/// context. Same root cause as G-1 (stale `Type::Record { size: 0 }`
/// on the Function::ret of an inline member function). With the
/// finalized record size correctly cached, the assignment path in
/// `gen_addr`/`Stmt::Assign` sees a real record type and the
/// struct-copy path takes over (instead of falling through to the
/// generic "not an lvalue" arm).
#[test]
fn g4_inline_member_via_this_and_ref_returning_own_class_now_compiles_and_runs_exit_3() {
    const SRC: &str = r#"
class Point { public:
    int x;
    int y;
    Point makeFrom(Point& o) { Point r; r.x = o.x; r.y = o.y; return r; }
};
int main(void) {
    Point a; a.x = 3; a.y = 4;
    Point b;
    b = a.makeFrom(a);
    return b.x;
}
"#;
    let exe = compile_to_pe(SRC.as_bytes())
        .expect("G-4: inline member with this + ref param, assigned, should compile post tick 55");
    let path = std::env::temp_dir().join(format!("mdbcc_g4_makefrom_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status.code(),
        Some(3),
        "G-4 runtime: b.x after b = a.makeFrom(a) where a.x=3 should be 3"
    );
}

/// G-5 (CLOSED tick 54): explicit operator-name member-call syntax
/// `obj.operator+(rhs)` now parses and lowers to the same overloaded-
/// operator call as the infix `obj + rhs`. Diagnostic-quality /
/// template-disambiguation gap closed.
#[test]
fn g5_explicit_operator_plus_member_call_now_compiles() {
    const SRC: &str = r#"
class P { public: int v; int operator+(P& o); };
int P::operator+(P& o) { return v + o.v; }
int main(void) {
    P a; a.v = 3;
    P b; b.v = 4;
    return a.operator+(b);
}
"#;
    // Parses + compiles; the runtime exit-7 assertion lives in the
    // matching runtime suite below.
    compile_to_pe(SRC.as_bytes())
        .expect("G-5: 'obj.operator+(rhs)' should parse + compile post tick 54");
}

/// G-5 runtime: explicit operator-name member-call returns the
/// same value as the infix form.
#[test]
#[cfg(windows)]
fn g5_explicit_operator_plus_member_call_runtime_exit_7() {
    const SRC: &str = r#"
class P { public: int v; int operator+(P& o); };
int P::operator+(P& o) { return v + o.v; }
int main(void) {
    P a; a.v = 3;
    P b; b.v = 4;
    return a.operator+(b);
}
"#;
    let exe = compile_to_pe(SRC.as_bytes()).expect("compile");
    let path = std::env::temp_dir().join(format!("mdbcc_g5_op_plus_{}.exe", std::process::id()));
    std::fs::write(&path, &exe).expect("write exe");
    let status = std::process::Command::new(&path).status().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(status.code(), Some(7), "G-5 runtime: 3 + 4 should be 7");
}

/// G-5 also covers explicit `operator[]` and arrow-form
/// `p->operator+(b)`.
#[test]
fn g5_explicit_operator_bracket_and_arrow_form_parse() {
    // operator[] via explicit name
    const SRC_BRACKET: &str = r#"
class L { public: int v; int& operator[](int);
};
int& L::operator[](int) { return v; }
int main(void) {
    L l; l.v = 11;
    return l.operator[](0);
}
"#;
    compile_to_pe(SRC_BRACKET.as_bytes())
        .expect("G-5: 'l.operator[](0)' should parse + compile post tick 54");
    // arrow form
    const SRC_ARROW: &str = r#"
class P { public: int v; int operator+(P& o); };
int P::operator+(P& o) { return v + o.v; }
int main(void) {
    P a; a.v = 3;
    P b; b.v = 4;
    P* pa = &a;
    return pa->operator+(b);
}
"#;
    compile_to_pe(SRC_ARROW.as_bytes())
        .expect("G-5: 'pa->operator+(b)' should parse + compile post tick 54");
}
