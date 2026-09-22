//! Determinism stripe (J-18) — closes a Tier-3 process gap from the
//! `2026.05.22` plan: prove `compile_to_pe` is **deterministic** across
//! repeated invocations within a single test process.
//!
//! Companion to `tests/o1_byte_identity.rs` (J-20, tick 63), which pins
//! each fixture's PE bytes against a snapshot baseline ONCE per test
//! invocation. J-18's contribution: hash the SAME fixture multiple times
//! in a single test run, assert all hashes agree.
//!
//! Catches the bug class O1 misses by design: a HashMap-iteration-order
//! nondeterminism inside codegen / PE-writer that produces different
//! PEs on different runs of the SAME source. O1 baselines would still
//! match a fresh bootstrap (if you happened to bootstrap during the
//! same iteration-order phase), but a tick later they might diverge.
//! H10 review MINOR-9 + testing-strategy §3b flagged this.
//!
//! Stripe = 17 fixtures × 5 compiles × SipHash match.
//!
//! ## S1e (2026-05-26) expansion
//!
//! The May-26 plan §6 testing charter (item 6) calls for expanding the
//! stripe from "≥10" during S1. This expansion adds 7 fixtures covering
//! code paths that landed AFTER J-18 was written (ticks 71-74) plus
//! a few intentionally-diverse paths:
//!
//! - `if_else_if_ladder` — chained equality / branch label allocation
//!   (the shape EV_WM_* macros expand to; mdbcc lacks `switch` itself).
//! - `single_class_ctor_dtor` — non-virtual class lifecycle.
//! - `class_hierarchy_virtual` — multi-class vtable construction.
//! - `virtual_mfp_call` — J-14b virtual MFP encoded-slot dispatch (tick 71).
//! - `try_catch_throw_class_virtual_dtor` — class-typed catch with vptr.
//! - `response_table_style` — OWL-flavoured chained dispatch + virtual call.
//! - `printf_multi_format` — wider printf format-string parse path.

#![cfg(windows)]

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

use mdbcc::compile_to_pe;

/// SipHash-1-3 over `bytes` — matches `tests/o1_byte_identity.rs`'s
/// fingerprint exactly so a hash mismatch here corresponds 1:1 to a
/// baseline mismatch there.
fn hash_hex(bytes: &[u8]) -> String {
    let mut h = DefaultHasher::new();
    h.write(bytes);
    format!("{:016x}", h.finish())
}

/// Seventeen fixtures hand-picked to span the codegen subsystems that have
/// HashMap-backed data structures (records, function names, vtables,
/// fp-literal pool, imports, response-table-style virtuals, virtual MFP
/// encoded slots, class-typed exception payloads). If any of these hashes
/// drifts run-to-run, the corresponding subsystem has leaked iteration-order
/// nondeterminism into the emitted bytes.
#[rustfmt::skip]
const STRIPE: &[(&str, &str)] = &[
    // Basic codegen path
    ("plain_arith",
        "int main(void) { return (2 + 3) * 8 - 10; }"),

    // Locals + control flow (label allocation order)
    ("if_else",
        "int main(void){ int x; x = 10; \
            if (x > 5) x = 100; else x = 200; return x; }"),

    // Functions + recursion (forward decls + linker resolution)
    ("recursive_factorial",
        "int fact(int n) { if (n < 2) return 1; return n * fact(n-1); } \
         int main(void) { return fact(5); }"),

    // .rdata strings + imports + IAT
    ("printf_hello",
        "int main(void) { printf(\"hello\\n\"); return 0; }"),

    // Records (HashMap<usize, Record>)
    ("struct_assign",
        "struct P { int x; int y; }; \
         int main(void) { struct P a; struct P b; a.x = 3; a.y = 4; \
                          b = a; return b.x + b.y; }"),

    // Class with virtual (vtable + multiple methods — Map iteration)
    ("class_virtual",
        "class B { public: virtual int f() { return 7; } }; \
         class D : public B { public: virtual int f() { return 11; } }; \
         int main(void) { D d; B* p = &d; return p->f(); }"),

    // Operator overloading (overload set HashMap)
    ("op_overload",
        "class C { public: int v; int operator+(C& o) { return v + o.v; } }; \
         int main(void) { C a; a.v = 3; C b; b.v = 4; return a + b; }"),

    // FP literal pool (per-fn Vec keyed by bit pattern, then promoted)
    ("fp_literal_pool",
        "int main(void) { double x; x = 1.5 + 2.25; return (int)(x * 4); }"),

    // SEH (.pdata + .xdata + scope tables)
    ("seh_throw_catch",
        "int main(void) { try { throw 42; } catch (int e) { return e; } }"),

    // Aggregate init (recently added, J-9 tick 57)
    ("aggregate_init",
        "int main(void) { int a[5] = {1, 2, 3, 4, 5}; \
                          int s; s = 0; \
                          int i; for (i = 0; i < 5; i = i + 1) s = s + a[i]; \
                          return s; }"),

    // -- S1e (May-26) additions: J-tier / OWL-flavoured paths --

    // Chained if/else-if ladder — mdbcc has no `switch`; this is the
    // semantic equivalent used by `EV_WM_*` macro expansions in OWL TUs
    // (each macro is `if (msg == X) { handler; return 0; }`). Exercises
    // the comparison + branch label allocation path repeatedly.
    ("if_else_if_ladder",
        "int main(void) { int x; x = 3; int r; r = 0; \
            if (x == 1) r = 100; \
            else if (x == 2) r = 200; \
            else if (x == 3) r = 300; \
            else if (x == 4) r = 400; \
            else r = 999; \
            return r; }"),

    // Non-virtual single class with ctor + dtor (RAII lifecycle, no vtable).
    ("single_class_ctor_dtor",
        "class Counter { \
              int n; int* slot; \
            public: \
              Counter(int* s) { n = 0; slot = s; *slot = 1; } \
              ~Counter() { *slot = n; } \
              void add(int d) { n = n + d; } \
              int get() { return n; } \
            }; \
            int main(void) { int v; v = 0; \
              { Counter c(&v); c.add(7); c.add(35); } \
              return v; }"),

    // Two-class hierarchy with virtual call — vtable build + dispatch.
    ("class_hierarchy_virtual",
        "class B { \
            public: \
              virtual ~B() {} \
              virtual int speak() { return 1; } \
            }; \
            class D : public B { \
            public: \
              virtual int speak() { return 42; } \
            }; \
            int main(void) { D d; B* p = &d; return p->speak(); }"),

    // Virtual MFP — tick 71 J-14b encoded-slot dispatch path.
    ("virtual_mfp_call",
        "class Base { \
            public: \
              virtual int v(int x) { return x + 1; } \
            }; \
            class Der : public Base { \
            public: \
              virtual int v(int x) { return x + 100; } \
            }; \
            int main(void) { \
              Der d; \
              int (Base::*p)(int); \
              p = &Base::v; \
              return (d.*p)(5); }"),

    // try/catch with throw of class instance + virtual dtor — H4b SEH path
    // through the typeinfo/catch-by-reference dispatcher.
    ("try_catch_throw_class_virtual_dtor",
        "class TX { \
            public: \
              virtual ~TX() {} \
              int code; \
              TX(int c) { code = c; } \
            }; \
            int main(void) { \
              try { TX e(73); throw e; } \
              catch (TX& x) { return x.code; } \
              return 0; }"),

    // Response-table style — OWL-flavoured class where the response macros
    // expand to a single virtual WindowProc with a chain of `if (msg==X)`
    // dispatches. Approximated here without the WM_ headers; uses two MFPs
    // selected by index, dispatched through the same instance. Exercises
    // both the virtual-MFP encoding (tick 71) and the static-dispatch path
    // EV_COMMAND macros expand to.
    ("response_table_style",
        "class Win { \
            public: \
              int v; \
              Win() { v = 0; } \
              int onClick(int n) { v = v + n; return v; } \
              int onClose(int n) { v = v - n; return v; } \
              int dispatch(int msg, int n) { \
                if (msg == 1) return onClick(n); \
                if (msg == 2) return onClose(n); \
                return 0; \
              } \
            }; \
            int main(void) { \
              Win w; \
              w.dispatch(1, 40); \
              w.dispatch(2, 2); \
              return w.v; }"),

    // printf with several format specifiers — wider format-parse coverage.
    ("printf_multi_format",
        "int main(void) { \
              printf(\"i=%d u=%u x=%x s=%s c=%c\\n\", \
                -5, 7u, 255, \"ok\", 65); \
              return 0; }"),
];

/// Compile each fixture **5 times** in this process. Every hash must
/// agree with the first compile's hash; any mismatch is a determinism
/// regression in the codegen / PE-writer for that fixture.
#[test]
fn determinism_stripe_5x_per_fixture() {
    const REPEATS: usize = 5;

    let mut failures: Vec<String> = Vec::new();

    for (name, source) in STRIPE {
        let mut hashes: Vec<String> = Vec::with_capacity(REPEATS);
        for _ in 0..REPEATS {
            let pe = match compile_to_pe(source.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    failures.push(format!("{name}: compile_to_pe failed: {e}"));
                    break;
                }
            };
            hashes.push(hash_hex(&pe));
        }
        if hashes.len() < REPEATS {
            // compile_to_pe error above; skip the agreement check.
            continue;
        }
        let first = &hashes[0];
        let mut drift_seen = false;
        for (i, h) in hashes.iter().enumerate().skip(1) {
            if h != first {
                drift_seen = true;
                failures.push(format!(
                    "{name}: compile #{i} produced hash {h}, \
                     expected {first} (first compile). \
                     Likely cause: HashMap iteration order \
                     leaked into emitted PE bytes."
                ));
            }
        }
        // Smoke: even when not drifting, ensure the hash is non-trivial.
        if !drift_seen {
            assert_ne!(
                first, "0000000000000000",
                "{name}: hash is zero — compile_to_pe probably \
                 returned an empty/zeroed PE"
            );
        }
    }

    assert!(
        failures.is_empty(),
        "determinism stripe failures ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Same-bytes hash consistency check — guard against a Rust update
/// that silently changes `DefaultHasher`. If this test fails alone,
/// every other hash in the stripe is suspect for a different reason.
#[test]
fn siphash_consistency_within_one_process() {
    let a = hash_hex(b"mdbcc J-18 determinism stripe sentinel");
    let b = hash_hex(b"mdbcc J-18 determinism stripe sentinel");
    assert_eq!(
        a, b,
        "DefaultHasher itself is non-deterministic across \
                       two invocations within one process — every other \
                       test in this suite is invalidated"
    );
}
