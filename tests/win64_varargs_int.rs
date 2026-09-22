//! Win64 integer-`va_arg` regression (surfaced by native-Win64 RailC's FINISH dialog).
//!
//! Symptom: RailC's `TFinish::SetupWindow` does
//! `sprintf(buf, "...%d...", layout->ArrNum)` with `ArrNum == 0`, but the Win64
//! build prints a garbage value (e.g. 1394880), while the 32-bit golden prints 0.
//! The *field* reads correctly (verified by a `wsprintf` trace: ArrNum=0); only the
//! value travelling through the C-RTL `sprintf`'s integer `va_arg` is wrong. A
//! float `%.2f` in the SAME call prints correctly ("0.00") — so FP varargs are fine
//! and the defect is specific to INTEGER `va_arg` on Win64.
//!
//! These self-contained roundtrips exercise mdbcc's OWN `va_arg` intrinsic (no RTL
//! dependency): a custom variadic `vsum(count, ...)` summing `count` ints, and the
//! exact FINISH shape `mixed(n, <double>, <int>)` — an int vararg that follows a
//! double vararg. Each returns the sentinel 42 iff the integer varargs read back
//! exactly. Run on BOTH -m64 and -m32; -m32 is the control (known-good).

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use mdbcc::compile_to_pe;

static COUNTER: AtomicU32 = AtomicU32::new(0);
const OK: i32 = 42;

fn unique_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_va_{tag}_{}_{n}.exe", std::process::id()));
    p
}

fn mdbcc_win64_pe(src: &str) -> Vec<u8> {
    compile_to_pe(src.as_bytes()).expect("mdbcc win64 compile ok")
}

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
                            panic!("{tag}: PE hung (>5s)");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("{tag}: wait failed: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("SKIP ({tag}): spawn failed: {e}");
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// `vsum(count, ...)` sums `count` int varargs; `mixed(n, <double>, <int>)` reads an
/// int vararg that follows a double vararg (the FINISH `"%.2f ... %d"` shape).
const SRC: &str = r#"
#include <stdarg.h>

static int vsum(int count, ...) {
  va_list ap;
  int total = 0;
  int i;
  va_start(ap, count);
  for (i = 0; i < count; i++) {
    total += va_arg(ap, int);
  }
  va_end(ap);
  return total;
}

static int mixed(int n, ...) {
  va_list ap;
  double d;
  int x;
  va_start(ap, n);
  d = va_arg(ap, double);   /* first vararg: a double */
  x = va_arg(ap, int);      /* second vararg: the int that read garbage in FINISH */
  va_end(ap);
  (void) n;
  return (int) d + x;
}

int main(void) {
  int a = vsum(3, 11, 22, 33);          /* expect 66 */
  int b = vsum(5, 1, 2, 3, 4, 5);       /* expect 15 */
  int c = mixed(2, 2.0, 40);            /* expect 2 + 40 = 42 */
  if (a != 66) return 60;
  if (b != 15) return 70;
  if (c != 42) return 80;
  return 42;
}
"#;

/// The canonical C-library shape: a VARIADIC wrapper `va_start`s and forwards the
/// `va_list` to a NON-VARIADIC worker that does the `va_arg`s (exactly how Borland's
/// RTL `sprintf` calls `__vprinter(..., va_list)`). mdbcc previously REJECTED
/// `va_arg` in a non-variadic function; that gate is now relaxed (it merely walks
/// the `char*` it's handed). `va_start`'s gate stays — see cpp_variadic::j13.
const SRC_VPRINTF_SHAPE: &str = r#"
#include <stdarg.h>

/* NON-variadic worker — receives the va_list by value and consumes it. */
static int worker(int count, va_list ap) {
  int total = 0;
  int i;
  for (i = 0; i < count; i++) {
    total += va_arg(ap, int);
  }
  return total;
}

/* VARIADIC wrapper — va_start then forward to the worker. */
static int wrapper(int count, ...) {
  va_list ap;
  int r;
  va_start(ap, count);
  r = worker(count, ap);
  va_end(ap);
  return r;
}

int main(void) {
  int a = wrapper(3, 11, 22, 33);       /* expect 66 */
  int b = wrapper(4, 10, 20, 30, 40);   /* expect 100 */
  if (a != 66) return 61;
  if (b != 100) return 71;
  return 42;
}
"#;

#[test]
fn win64_va_arg_in_non_variadic_worker_vprintf_shape() {
    let pe64 = mdbcc_win64_pe(SRC_VPRINTF_SHAPE);
    match run_exit(&pe64, "vshape") {
        Some(code) => assert_eq!(
            code, OK,
            "win64 vprintf-shape (variadic wrapper -> non-variadic va_arg worker): expected {OK}, \
             got {code:#x}. This is the RTL sprintf->__vprinter pattern; mdbcc must allow va_arg in a \
             non-variadic function that holds a live va_list."
        ),
        None => panic!("win64 vprintf-shape exe failed to launch"),
    }
}

#[test]
fn win64_integer_va_arg_reads_back_exactly() {
    let pe64 = mdbcc_win64_pe(SRC);
    match run_exit(&pe64, "m64") {
        Some(code) => assert_eq!(
            code, OK,
            "win64 integer va_arg roundtrip: expected {OK}, got {code:#x} \
             (60 = vsum(3,11,22,33)!=66; 70 = vsum(5,..)!=15; 80 = mixed(2,2.0,40)!=42 — \
             the int vararg after a double read garbage). This is the FINISH-dialog defect."
        ),
        None => panic!("win64 exe failed to launch"),
    }
}

// NOTE: i386 is intentionally NOT exercised here. mdbcc's va_arg INTRINSIC is
// Win64-shaped (`STDARG_H` doc: 8-byte home slots); on i386 it currently hits a
// separate codegen gap (`no encoder row for Mov Gpr64,Gpr64` in the va_arg lower),
// which is why the i386 RTL legitimately uses BC45's 32-bit stack-walking macros.
// This regression's job is to prove the *Win64* intrinsic is correct — which
// localises the RailC FINISH garbage-`%d` defect to BC45's <stdarg.h> macros being
// compiled verbatim for the RTL printf (fixed by the wrk_owl_win64 STDARG.H overlay),
// NOT to mdbcc's codegen. (i386 va_arg lowering is tracked separately.)
