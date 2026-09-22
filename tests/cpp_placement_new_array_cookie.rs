//! MDBCC-01 array-new cookie fix — the allocator-placement form
//! `new(alloc)T[n]` for a CLASS element (`array_needs_cookie` = ctor OR dtor).
//!
//! Root cause (see `wrk_docs/2026.06.13 - HLD - mdbcc Win64 array-new cookie
//! fix.md`): `gen_placement_new_array`'s allocator form produced the block
//! COOKIE-LESS, but the (unchanged) `gen_delete` array path reads an element
//! count at `payload-cookie` and `HeapFree`s `payload-cookie`. For a class
//! element `delete[]` therefore freed a mis-offset pointer → heap corruption
//! (Win64 `0xC0000374`, active; i386 latent/identical).
//!
//! These are SELF-CONTAINED run-and-assert roundtrips (no cl/bcc32 oracle
//! dependency): a minimal allocator `A` whose `operator new[](size_t, A&)`
//! forwards to the global `::operator new[]` (= raw HeapAlloc, no private
//! header — the BIDS `TStandardAllocator` model, ALLOCTR.H:47-49), plus a
//! class `C` that bumps static ctor/dtor counters. Each test runs the mdbcc-
//! built program on BOTH -m64 (`compile_to_pe`) and -m32 (i386 codegen + the
//! in-tree linker on WOW64) and asserts a success sentinel that encodes
//! `clean-exit && ctors==N && dtors==N` plus a post-`delete[]` alloc+free heap
//! validation (O1.e) and the O2 cookie-distance symmetry `*((size_t*)p-1)==N`
//! (read pointer-width via `((void**)p)[-1] == (void*)N`, target-portable).
//!
//! Pre-fix these FAIL on Win64 (`0xC0000374` / wrong dtor count); post-fix
//! both targets return the sentinel `42`.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::compile_to_pe;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Success sentinel returned by every variant's `main` on a clean roundtrip.
const OK: i32 = 42;

fn unique_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_placenew_{tag}_{}_{n}.exe", std::process::id()));
    p
}

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// mdbcc -m64: source → runnable PE64.
fn mdbcc_win64_pe(src: &str) -> Vec<u8> {
    compile_to_pe(src.as_bytes()).expect("mdbcc win64 compile ok")
}

/// mdbcc -m32: source → PE32 via the i386 backend + the in-tree linker
/// (exactly as `tests/i386_run.rs` does).
fn mdbcc_i386_pe(src: &str) -> Vec<u8> {
    let resolver = DefaultResolver {
        base_dir: PathBuf::from("."),
    };
    let obj = compile_to_object_with_target(src.as_bytes(), "main.c", &resolver, TargetKind::Win32)
        .expect("mdbcc i386 compile ok");
    link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32")
}

/// Run a PE with a 5 s wall-clock timeout. `Some(code)` on clean exit; `None`
/// only if the spawn/write failed (WOW64 refused the image — a loud skip, not
/// a codegen verdict). A hang (>5 s) is a hard failure (heap corruption can
/// wedge teardown); a crash returns its `STATUS_*` exit code.
fn run_exit(pe: &[u8], tag: &str) -> Option<i32> {
    let path = unique_path(tag);
    if std::fs::write(&path, pe).is_err() {
        eprintln!("SKIP ({tag}): could not write temp exe");
        return None;
    }
    let result = match Command::new(&path).spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(5) {
                            let _ = child.kill();
                            panic!("{tag}: PE hung (>5s) — likely heap corruption wedged teardown");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("{tag}: wait failed: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("SKIP ({tag}): spawn failed (WOW64 refused image?): {e}");
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// Build `src` with mdbcc on BOTH targets and assert the success sentinel.
/// -m64 must launch (a launch failure there is a hard fail); -m32 loud-skips
/// only if WOW64 refuses to spawn the image (environment, not codegen).
fn check_both(tag: &str, src: &str) {
    let pe64 = mdbcc_win64_pe(src);
    match run_exit(&pe64, &format!("{tag}_m64")) {
        Some(code) => assert_eq!(
            code, OK,
            "[{tag}] win64 placement-array-new roundtrip: expected {OK}, got {code:#x} \
             (0xC0000374 = heap corruption from the cookie mismatch; 50/55/60/70 = a \
             miscount/cookie/heap check inside main)"
        ),
        None => panic!("[{tag}] win64 exe failed to launch"),
    }
    let pe32 = mdbcc_i386_pe(src);
    match run_exit(&pe32, &format!("{tag}_m32")) {
        Some(code) => assert_eq!(
            code, OK,
            "[{tag}] win32 placement-array-new roundtrip: expected {OK}, got {code:#x}"
        ),
        None => eprintln!("NOTE [{tag}]: win32 exe did not launch (WOW64?) — skipped"),
    }
}

// ---------------------------------------------------------------------------
// Source builders
// ---------------------------------------------------------------------------

/// The minimal BIDS-shaped allocator: `operator new[](size_t, A&)` forwarding
/// to the raw global `::operator new[]` (HeapAlloc, no private header) — the
/// `TStandardAllocator` model the fix is scoped to (HLD D7). `size_t` is
/// avoided (self-contained TU, no <stddef.h>); `unsigned long` is a valid
/// `operator new[]` size parameter on both targets.
const ALLOCATOR: &str = "\
    struct A { int tag; };\n\
    void* operator new[](unsigned long n, A& a) { return ::operator new[](n); }\n";

/// Common tail: read the O2 cookie symmetry, `delete[] p`, then a SECOND
/// alloc+free (O1.e heap validation), then encode the verdict in the exit
/// code. `ac`/`ad` are the ctor/dtor counts the caller wired up.
fn verdict_tail(n: i32) -> String {
    format!(
        "    int cookie_ok = (((void**)p)[-1] == (void*){n}) ? 1 : 0;\n\
             delete[] p;\n\
             int ad = g_dtors;\n\
             int* q = new int[4];\n\
             q[0]=1; q[1]=2; q[2]=3; q[3]=4;\n\
             int s = q[0]+q[3];\n\
             delete[] q;\n\
             if (ac != {n}) return 50;\n\
             if (cookie_ok != 1) return 55;\n\
             if (ad != {n}) return 60;\n\
             if (s != 5) return 70;\n\
             return 42;\n\
         }}\n"
    )
}

/// (a)/(d) ctor+dtor element, parametrised by `n`.
fn src_ctor_dtor(n: i32) -> String {
    format!(
        "int g_ctors = 0;\n\
         int g_dtors = 0;\n\
         {ALLOCATOR}\
         struct C {{ int v; C() {{ g_ctors = g_ctors + 1; v = 7; }} ~C() {{ g_dtors = g_dtors + 1; }} }};\n\
         int main() {{\n\
             A a;\n\
             C* p = new(a) C[{n}];\n\
             int ac = g_ctors;\n\
         {}",
        verdict_tail(n)
    )
}

// ---------------------------------------------------------------------------
// O1 matrix
// ---------------------------------------------------------------------------

/// O1(a): the headline — allocator-placement array of a ctor+dtor class.
/// Pre-fix Win64: `delete[]` reads a garbage cookie at `p-8`, frees `p-8`
/// → `0xC0000374`. Post-fix: cookie@block+0, payload=block+8, `delete[]`
/// runs exactly N dtors and frees the real base.
#[test]
fn placement_array_ctor_dtor_roundtrip() {
    check_both("ctor_dtor_n3", &src_ctor_dtor(3));
}

/// O1(d): larger N so the dtor loop / size arithmetic isn't only exercised at
/// the smallest case.
#[test]
fn placement_array_ctor_dtor_large_n() {
    check_both("ctor_dtor_n64", &src_ctor_dtor(64));
}

/// O1(b): DTOR-ONLY class (no user ctor). This is the path that previously
/// mis-routed through the cookie-less `ctor.is_none()` branch; the fix gates
/// the cookie on `array_needs_cookie` (ctor OR dtor), so a dtor-only element
/// gets the cookie (and `delete[]` runs N dtors) even with no construction
/// loop. No `g_ctors` to read, so the ctor check is a constant pass.
#[test]
fn placement_array_dtor_only_roundtrip() {
    let n = 5;
    let src = format!(
        "int g_ctors = 0;\n\
         int g_dtors = 0;\n\
         {ALLOCATOR}\
         struct C {{ int v; ~C() {{ g_dtors = g_dtors + 1; }} }};\n\
         int main() {{\n\
             A a;\n\
             C* p = new(a) C[{n}];\n\
             int ac = {n};\n\
         {}",
        verdict_tail(n)
    );
    check_both("dtor_only_n5", &src);
}

/// O1(c): IMPLICIT non-trivial dtor via a MEMBER with a dtor (class `C` has no
/// user-declared dtor, but member `M` does). This exercises the
/// `array_needs_cookie` predicate completeness concern (Codex #5). The
/// producer (new) and consumer (delete) both consult the SAME predicate, so
/// whatever `array_needs_cookie` decides, the two AGREE — the block is freed at
/// the right base and the heap stays intact. We assert a clean roundtrip and a
/// valid post-delete heap (the member-dtor count is reported, not asserted,
/// since implicit-dtor synthesis is orthogonal to the cookie symmetry).
#[test]
fn placement_array_implicit_dtor_via_member() {
    let n = 4;
    // No O2 cookie assertion here (the predicate may legitimately classify an
    // implicit-dtor class either way); assert only clean exit + heap validity.
    let src = format!(
        "int g_dtors = 0;\n\
         {ALLOCATOR}\
         struct M {{ int x; ~M() {{ g_dtors = g_dtors + 1; }} }};\n\
         struct C {{ M m; int v; C() {{ v = 7; }} }};\n\
         int main() {{\n\
             A a;\n\
             C* p = new(a) C[{n}];\n\
             delete[] p;\n\
             int* q = new int[4];\n\
             q[0]=1; q[3]=4;\n\
             int s = q[0]+q[3];\n\
             delete[] q;\n\
             if (s != 5) return 70;\n\
             return 42;\n\
         }}\n"
    );
    check_both("implicit_dtor_member_n4", &src);
}

/// Negative control: a TRIVIAL element (no ctor, no dtor) stays cookie-less on
/// the allocator-placement path (byte-identical to pre-fix). The roundtrip
/// must still run cleanly — the block IS the value and `delete[]` frees it raw.
#[test]
fn placement_array_trivial_element_stays_cookieless() {
    let n = 8;
    let src = format!(
        "{ALLOCATOR}\
         struct C {{ int v; int w; }};\n\
         int main() {{\n\
             A a;\n\
             C* p = new(a) C[{n}];\n\
             p[0].v = 3; p[{m}].w = 2;\n\
             int s = p[0].v + p[{m}].w;\n\
             delete[] p;\n\
             int* q = new int[4];\n\
             q[0]=1; q[3]=4;\n\
             int s2 = q[0]+q[3];\n\
             delete[] q;\n\
             if (s != 5) return 50;\n\
             if (s2 != 5) return 70;\n\
             return 42;\n\
         }}\n",
        m = n - 1
    );
    check_both("trivial_cookieless_n8", &src);
}

/// Part 2 (codegen lock): the Win64 allocator-placement ctor loop must use
/// REX.W (64-bit) pointer arithmetic so the payload/`this` computation isn't
/// truncated for heap addresses ≥ 4 GB. Pre-Part-2 the loop emitted 32-bit-only
/// `add eax,[rbp-payload]` (`03 85 ..`) / `inc dword [rbp-iter]` (`FF 85 ..`);
/// the widened loop emits `add rax,[rbp-payload]` (`48 03 85 ..`) /
/// `inc qword [rbp-iter]` (`48 FF 85 ..`), mirroring gen_new_array. This TU's
/// ONLY construction loop is the allocator-placement one, so the REX.W
/// signature pins the widening directly in the emitted image.
#[test]
fn placement_array_ctor_loop_is_64bit_on_win64() {
    let src = format!(
        "int g_ctors = 0;\n\
         {ALLOCATOR}\
         struct C {{ int v; C() {{ g_ctors = g_ctors + 1; }} }};\n\
         int main() {{ A a; C* p = new(a) C[3]; return p != 0 ? 0 : 1; }}\n"
    );
    let pe = mdbcc_win64_pe(&src);
    assert!(
        window_contains(&pe, &[0x48, 0x03, 0x85]),
        "Win64 placement ctor loop must emit `add rax,[rbp-payload]` (REX.W: 48 03 85)"
    );
    assert!(
        window_contains(&pe, &[0x48, 0xFF, 0x85]),
        "Win64 placement ctor loop must emit `inc qword [rbp-iter]` (REX.W: 48 FF 85)"
    );
}

/// True if `needle` occurs as a contiguous byte window in `hay`.
fn window_contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
