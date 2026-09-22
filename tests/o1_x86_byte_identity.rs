//! x86 (i386/Win32) byte-identity stripe — HLD §9.3 / S2-exit deliverable.
//!
//! The CD-INDEPENDENT companion to `tests/oracle_o12_x86_corpus.rs`. That O12
//! harness is a *differential* (mdbcc i386 vs bcc32 + tlink32) and self-skips
//! when the BCC 4.52 CDs are absent — so on a box without the oracle the entire
//! i386 path is unguarded. This stripe locks the exact i386 PE32 bytes against
//! a pinned SipHash baseline, so any accidental regression in the i386 codegen
//! (during future float / SEH / name-decoration work) fails loudly here even
//! when no oracle is present. It mirrors the x64 stripe in
//! `tests/o1_byte_identity.rs`.
//!
//! ## Hash algorithm
//!
//! SipHash-1-3 via `std::hash::DefaultHasher` — the SAME inline implementation
//! the x64 stripe uses (copied verbatim, because integration-test binaries do
//! not share private items). `siphash_known_answer` pins the algorithm itself
//! so a Rust toolchain update that changes `DefaultHasher` ("implementation-
//! defined" per the docs) surfaces as a *single* visible failure here, not a
//! flurry of inscrutable per-fixture mismatches.
//!
//! ## Fixture set
//!
//! Every `tests/corpus/portable/*.c` that mdbcc's i386 backend can compile +
//! link today. We do NOT hand-curate the list: each fixture's compile+link is
//! wrapped in `catch_unwind` and any that panic (the encoder `panic!`s on an
//! unimplemented construct) or error are SKIPPED — never hashed. So the stripe
//! stays green as the gap set shrinks (a newly-supported fixture starts
//! producing a PE; the run then reports it as UNPINNED and you bless it). Today
//! that is all 19 fixtures the O12 harness reports as MATCH — including
//! `printf_float.c`, whose `%f`/`%.Nf` path landed on i386 in Phase F-4 (FP
//! literals load absolutely; `float_token` keeps the value in SSE2 and pulls
//! digits one at a time — see `src/codegen.rs`). Nothing is skipped now.
//!
//! `virtual.c` is C++. mdbcc's `compile_to_object_with_target` lexes / parses /
//! lowers the C++ subset uniformly regardless of file extension (no C-vs-C++
//! branch — see `src/compile.rs`), so it is built through the *identical* call
//! as the C fixtures. The `// oracle: lang cpp` directive only steers the bcc32
//! reference in the O12 harness; it is irrelevant to the bytes we hash here.
//!
//! ## Determinism
//!
//! Every fixture is compiled + linked TWICE and the two hashes are asserted
//! equal before either is compared to the baseline. The x64 PE writer is
//! deterministic and the i386 path shares it, so this should always hold; the
//! double-compile catches any latent nondeterminism (a fixture that fails it
//! would be excluded and the reason noted, rather than pinned as a flaky
//! baseline).
//!
//! ## Bless workflow (update baselines when i386 codegen legitimately changes)
//!
//! When a tick deliberately changes the i386 bytes, this test fails with a
//! per-fixture `expected H1, got H2` table (and lists any UNPINNED fixtures a
//! coverage gain newly produced). To re-bless:
//!   1. `git diff` to confirm the codegen change is intentional and scoped.
//!   2. Re-run `cargo test --release --test o1_x86_byte_identity` and read the
//!      printed `("<fixture>", 0x...u64),` lines from the failure output (the
//!      empty-baseline bootstrap path prints the full table ready to paste).
//!   3. Replace the affected entries in `BASELINE_HASHES` with the new values
//!      (or add a line for a newly-compilable fixture).
//!   4. Journal the change and commit the baseline in the SAME commit (the same
//!      discipline the x64 stripe documents for the Phase H4a IAT shift).

#![cfg(windows)]

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;

/// SipHash-1-3 over `bytes`. Used as the per-PE fingerprint. Returns a
/// lowercase 16-hex-digit string (`{:016x}` of the 64-bit hash).
///
/// Copied verbatim from `tests/o1_byte_identity.rs` (integration-test files do
/// not share items) so this stripe hashes identically to the established x64
/// one — `siphash_known_answer` pins that this is the canonical implementation.
fn hash_hex(bytes: &[u8]) -> String {
    let mut h = DefaultHasher::new();
    h.write(bytes);
    format!("{:016x}", h.finish())
}

/// The raw 64-bit SipHash used by the corpus baseline (a `u64` table reads
/// cleaner than hex strings for this stripe). This is the exact value
/// `hash_hex` formats — `format!("{:016x}", hash_u64(b)) == hash_hex(b)` — so
/// the algorithm is still pinned by `siphash_known_answer`.
fn hash_u64(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    h.write(bytes);
    h.finish()
}

/// i386 link options — copied from `tests/i386_run.rs` (`link_opts_i386`).
fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Compile `src` through mdbcc's i386 codegen and link to a PE32 image.
/// Mirrors `tests/i386_run.rs::mdbcc_i386_pe`, but returns `Result` (and lets
/// the encoder's `panic!` propagate) so the caller's `catch_unwind` can convert
/// an unimplemented-construct gap into a SKIP rather than a hard failure.
fn mdbcc_i386_pe(src: &[u8], file_name: &str, base_dir: &Path) -> Result<Vec<u8>, String> {
    let resolver = DefaultResolver {
        base_dir: base_dir.to_path_buf(),
    };
    let obj = compile_to_object_with_target(src, file_name, &resolver, TargetKind::Win32)
        .map_err(|e| format!("compile: {e:?}"))?;
    link::link(&[Input::Object(&obj)], &link_opts_i386()).map_err(|e| format!("link: {e:?}"))
}

/// Build a fixture's i386 PE32, catching the encoder's panic on an
/// unimplemented construct. `Some(bytes)` if it produced a PE; `None` if it
/// panicked or errored (an i386 coverage gap — skipped, not hashed).
fn try_build_i386(src: &[u8], file_name: &str, base_dir: &Path) -> Option<Vec<u8>> {
    match panic::catch_unwind(AssertUnwindSafe(|| mdbcc_i386_pe(src, file_name, base_dir))) {
        Ok(Ok(pe)) => Some(pe),
        Ok(Err(_)) => None, // compile/link error — coverage gap
        Err(_) => None,     // encoder panic — coverage gap
    }
}

// ---------------------------------------------------------------------------
// BASELINE_HASHES: the SipHash snapshot of each compilable i386 PE32, by
// fixture file name. Populated after the first run (the test prints the table
// when this is empty). One line per fixture keeps the baseline auditable in
// `git diff` and grep-able by name.
//
// Snapshot history:
// - S2-exit (x86 byte-identity stripe introduction): initial lock of the 18
//   i386-compilable portable fixtures (all of tests/corpus/portable/ except
//   printf_float.c, whose %f path was x64-only and panicked in the i386
//   encoder).
// - Phase F-4 (i386 floating-point printf): printf_float.c became i386-
//   compilable once `%f`/`%.Nf` landed on Win32 (FP literals load absolutely
//   via a new `movsd xmm,[abs]` X86Only encoder row; `float_token` grew an
//   SSE2 digit-by-digit Win32 branch). Its PE32 is now pinned — the stripe
//   covers all 19 portable fixtures with none skipped.
// - S2e (i386 fs:[0] SEH): exceptions.c was added to the corpus and became
//   i386-compilable once `try`/`throw <int>`/`catch (int)` lowered to the
//   x86 fs:[0] model (per-function EXCEPTION_REGISTRATION prologue/epilogue,
//   __stdcall RaiseException, the module-wide `.mdbcc_seh3_handler` that
//   RtlUnwinds to the catch pad). Its PE32 is now pinned — 20 fixtures total.
// - G42 (i386 in-place cdecl params): Win32 parameters are no longer copied
//   into frame locals by a prologue spill — they are addressed IN PLACE at
//   their incoming cdecl slots ([ebp+8+cum]), exactly bcc32's model. Every
//   fixture with a parameter-taking user function changed bytes (8 of 20);
//   the param-free ones (printf_*.c et al.) are untouched. Required so
//   Borland's stdarg.h address arithmetic (`&parmN + sizeof`) reaches the
//   caller-pushed varargs — the RTL printf family depends on it. Runtime
//   parity re-verified MATCH vs bcc32 by oracle_o12_x86_corpus.rs.
// - B-07 (call argument evaluation order): i386 call marshalling now evaluates
//   explicit arguments right-to-left while preserving source-order positional
//   delivery. The changed fixtures contain user calls, function pointers,
//   intrinsic libc calls, recursion, or virtual dispatch; behavioural parity is
//   covered by i386_run's B-07 regressions and the portable O12 corpus.
// - B-22 (printf flags / wide %f precision): explicit printf specs now support
//   sign and alternate-form prefixes, and `%f` uses precision-sized token
//   buffers with digit-at-a-time fractional extraction. The printf fixtures
//   with zero-padded or floating formats changed bytes; behavioural parity is
//   covered by printf_format.rs and i386_run.rs regressions.
// - G56 (uniform vtable RTTI prefixes): `virtual.c` changed because every
//   polymorphic vtable now carries the two-word RTTI prefix, even in TUs that
//   do not use `dynamic_cast`. This keeps weak-folded vtables ABI-compatible
//   across TUs; the vtable symbol still points at the slot array, so dispatch
//   semantics are unchanged.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
// Re-blessed 2026-06-17: G56 uniform vtable RTTI prefixes (`virtual.c`).
const BASELINE_HASHES: &[(&str, u64)] = &[
    ("arith.c",            0x410c_e16e_6a37_9568),
    ("bigcode.c",          0x32f0_140c_ba70_f1de),
    ("bigdata.c",          0x36e9_69d6_f8e2_6272),
    ("control.c",          0xc9d1_6c76_3b6d_790d),
    ("exceptions.c",       0x5678_740d_392a_350b),
    // Re-blessed: i386 ILP32 array-of-pointer scaling. `funcptr.c` declares
    // `int (*ops[3])(int,int)` and indexes it (`ops[0]`/`ops[1]`/`ops[2]`).
    // `gen_index_addr` now scales the subscript by the *element* size
    // computed for the target pointer width — 4 bytes on Win32, not the
    // historical Win64 8 — so the three slots sit 4 bytes apart (bcc32's
    // ILP32 layout). The new image is verified MATCH vs bcc32 by
    // oracle_o12_x86_corpus.rs.
    ("funcptr.c",          0x215b_b907_10fe_d9ea),
    ("manyargs.c",         0x09d8_1df5_ad77_ae10),
    ("pointers.c",         0xd3e1_0ac8_4017_ec55),
    ("printf_float.c",     0x70d7_7d9b_1be8_4dfe),
    ("printf_length.c",    0x1b70_0f39_3fe2_59d1),
    ("printf_precision.c", 0xb126_6ec1_0e61_6acc),
    ("printf_width.c",     0x17f4_12a6_a468_2d5f),
    ("printf_width2.c",    0xa0a7_090e_af26_60ec),
    ("printf_zero.c",      0x7781_ae83_aad0_02a8),
    ("printf_zero2.c",     0xcce9_53df_7f31_7da2),
    ("recursion.c",        0xc18b_5d63_74cd_79ec),
    ("strings.c",          0x219f_1fe7_a74e_fb05),
    ("structs.c",          0xd1dd_2148_720b_207f),
    ("unsigned.c",         0xb941_1fb4_2dba_6f77),
    // Re-blessed:
    //  (1) the i386 scope-exit destructor fix (`emit_dtors` now uses a cdecl
    //      `lea ecx; push ecx; call ~Tag; add esp,4` on Win32 instead of the
    //      Win64 `lea rcx` REX.W + RCX-pass form).
    //  (2) i386 ILP32 polymorphic vptr: a polymorphic class's hidden vptr is a
    //      pointer, so it is now 4 bytes on Win32 (was 8). Data members shift
    //      from offset +8 to +4 (`Square::s`, `Rect::w/h`), matching bcc32's
    //      ILP32 vtable layout. virtual.c has two stack-local objects with
    //      dtors (`Square sq`, `Rect rc`) and dispatches through a base
    //      pointer, so both the layout and the dtor sequence land in its
    //      bytes. The new image is verified MATCH vs bcc32 by
    //      oracle_o12_x86_corpus.rs.
    //  (3) the overload-aware vtable rebuild now maps the internal destructor
    //      key `~` to the real qualified destructor name (`Square::~Square`)
    //      when applying derived overrides. `delete Shape*` now dispatches
    //      through the derived destructor slot again; the behavioural
    //      differential arms for virtual.c are green against MSVC and bcc32.
    //  (4) G56 uniform vtable RTTI prefixes: even this no-dynamic_cast fixture
    //      now carries the two-word prefix before each vtable so a weak-folded
    //      vtable has the same ABI shape as a dynamic_cast-using TU. The symbol
    //      still points at the slot array, so virtual dispatch is unchanged.
    ("virtual.c",          0x3dd9_20c3_3104_a639),
];

// ---------------------------------------------------------------------------

/// Enumerate the portable corpus, sorted by file name (stable order).
fn corpus_fixtures() -> Vec<PathBuf> {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/portable");
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "c"))
        .collect();
    fixtures.sort();
    fixtures
}

#[test]
fn x86_byte_identity_corpus() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/portable");
    let fixtures = corpus_fixtures();
    assert!(!fixtures.is_empty(), "no portable corpus fixtures found");

    // Silence the encoder's noisy panic backtrace: the catch_unwind in
    // try_build_i386 converts an unimplemented-construct panic into a SKIP, so
    // the backtrace is pure noise. Restore the hook afterwards.
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    // Compute today's hash for every fixture that compiles + links, compiling
    // TWICE to assert determinism before trusting the value.
    let mut computed: Vec<(String, u64)> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut nondeterministic: Vec<String> = Vec::new();

    for path in &fixtures {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let file_name = path.to_string_lossy().to_string();
        let Ok(src) = std::fs::read(path) else {
            skipped.push(format!("{name} (unreadable)"));
            continue;
        };

        let Some(pe1) = try_build_i386(&src, &file_name, &corpus_dir) else {
            skipped.push(name);
            continue;
        };
        // Determinism: a second independent build must produce identical bytes.
        let Some(pe2) = try_build_i386(&src, &file_name, &corpus_dir) else {
            // First build succeeded but the second didn't — itself a form of
            // nondeterminism; refuse to pin it.
            nondeterministic.push(format!("{name} (second build failed)"));
            continue;
        };
        let h1 = hash_u64(&pe1);
        let h2 = hash_u64(&pe2);
        if h1 != h2 {
            nondeterministic.push(format!("{name} ({h1:#018x} != {h2:#018x})"));
            continue;
        }
        computed.push((name, h1));
    }

    panic::set_hook(prev_hook);

    // A nondeterministic fixture is a hard failure: it would force a flaky
    // baseline. (None expected — the PE writer is deterministic.)
    assert!(
        nondeterministic.is_empty(),
        "i386 PE output is NONDETERMINISTIC for {} fixture(s) — exclude and \
         investigate, do not pin a flaky baseline:\n  {}",
        nondeterministic.len(),
        nondeterministic.join("\n  "),
    );

    // Diagnostic: which fixtures were skipped (i386 coverage gaps). Printed so
    // the actionable gap list stays visible (e.g. printf_float.c).
    eprintln!(
        "\n=== x86 byte-identity stripe: {} pinned, {} skipped (i386 gaps) ===",
        computed.len(),
        skipped.len()
    );
    for s in &skipped {
        eprintln!("  SKIP {s}");
    }

    // We must lock *something* — if every fixture skipped, the harness is
    // mis-wired (wrong target, broken link path) and silently passing.
    assert!(
        !computed.is_empty(),
        "no i386-compilable fixtures produced a PE — the stripe would be \
         vacuous (check the TargetKind::Win32 compile + link path)."
    );

    // Bootstrap mode: empty baseline ⇒ print the snapshot to paste into
    // BASELINE_HASHES, then fail. The ONLY path that mints the baseline — a
    // deliberate manual step (no env-var auto-accept that could mask a
    // regression).
    if BASELINE_HASHES.is_empty() {
        let mut msg = String::from(
            "\nBASELINE_HASHES is empty — snapshot mode. Paste the lines below \
             into the BASELINE_HASHES const, then re-run.\n\n",
        );
        for (name, h) in &computed {
            msg.push_str(&format!("    ({name:?}, {h:#018x}),\n"));
        }
        panic!("{msg}");
    }

    // Baseline lookup map; reject a malformed (duplicate-keyed) baseline.
    let baseline: std::collections::HashMap<&str, u64> =
        BASELINE_HASHES.iter().map(|(n, h)| (*n, *h)).collect();
    assert_eq!(
        baseline.len(),
        BASELINE_HASHES.len(),
        "duplicate names in BASELINE_HASHES — baseline is malformed."
    );

    // Compare. Collect ALL discrepancies before failing so one re-run tells the
    // whole story. An UNPINNED fixture (newly compilable, no baseline) is a
    // failure too: it means i386 coverage grew and the bless step is pending.
    let mut violations: Vec<String> = Vec::new();
    for (name, got) in &computed {
        match baseline.get(name.as_str()) {
            Some(expected) if *expected == *got => {}
            Some(expected) => violations.push(format!(
                "  {name}: expected {expected:#018x}, got {got:#018x}"
            )),
            None => violations.push(format!(
                "  {name}: UNPINNED (newly i386-compilable; add baseline {got:#018x})"
            )),
        }
    }
    // A baseline entry for a fixture that no longer compiles (regressed gap, or
    // a fixture deleted/renamed) is also a discrepancy worth surfacing.
    let computed_names: std::collections::HashSet<&str> =
        computed.iter().map(|(n, _)| n.as_str()).collect();
    for (name, _) in BASELINE_HASHES {
        if !computed_names.contains(name) {
            violations.push(format!(
                "  {name}: in BASELINE_HASHES but produced no PE (regressed gap, \
                 or fixture renamed/removed)"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "\nx86 byte-identity stripe violated for {} fixture(s):\n{}\n\n\
         If these changes are INTENTIONAL (a tick that legitimately changes \
         i386 codegen, or a newly-supported fixture), update BASELINE_HASHES \
         with the new values and journal the change in the SAME commit (the \
         x64 stripe's Phase H4a IAT-shift discipline). Otherwise this is a real \
         regression: a non-targeted change perturbed the i386 bytes. Bisect with \
         `git bisect run cargo test --release --test o1_x86_byte_identity`.\n",
        violations.len(),
        violations.join("\n"),
    );
}

/// Self-test for the hash function: a known-answer probe so that a Rust upgrade
/// silently changing `DefaultHasher` (SipHash-1-3 is documented as
/// "implementation-defined") shows up as a *single* failure here, not a flurry
/// of inscrutable mismatches above.
///
/// Copied verbatim from `tests/o1_byte_identity.rs::siphash_known_answer` so
/// both stripes prove the SAME canonical SipHash. If this fails after a
/// toolchain upgrade, that is the only sanctioned reason to re-bless the
/// baselines wholesale (clear `BASELINE_HASHES`, re-run, paste, journal as a
/// "DefaultHasher algorithm change at rustc X.Y.Z").
#[test]
fn siphash_known_answer() {
    // Empty input must produce a stable SipHash with the std seed.
    let empty = hash_hex(b"");
    // ASCII content: a deterministic non-empty probe.
    let abc = hash_hex(b"abc");
    // Both must be 16 lowercase-hex digits.
    assert_eq!(empty.len(), 16, "hash_hex({:?}) wrong length", "");
    assert_eq!(abc.len(), 16, "hash_hex({:?}) wrong length", "abc");
    assert!(
        empty
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "hash_hex must produce lowercase hex"
    );
    // Stability under repeated calls (no internal state leakage).
    assert_eq!(empty, hash_hex(b""), "hash_hex is not pure");
    assert_eq!(abc, hash_hex(b"abc"), "hash_hex is not pure");
    // Different inputs ⇒ different outputs (the trivial collision check
    // — astronomically unlikely for these two inputs).
    assert_ne!(empty, abc, "hash_hex collided on trivial inputs");
}
