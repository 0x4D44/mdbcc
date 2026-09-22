//! O15 — Borland header preprocessor-acceptance oracle (Stone S3).
//!
//! Measures how many of the real `\BC45\INCLUDE\*.h` headers mdbcc's
//! preprocessor (translation phases 1–4: lex + `pp::preprocess`) accepts
//! *without error or panic*. This is the S3-exit metric (target: all 246) and
//! — more usefully right now — the actionable gap list: every REJECT is
//! grouped by its preprocessor-error cause so the next S3 ticks know exactly
//! what to fix.
//!
//! Scope: **preprocessor acceptance only**. A header that preprocesses cleanly
//! still says nothing about whether it *parses* or *type-checks* — that is
//! S4/S5. ACCEPT here means "phase-4 produced a token stream without raising a
//! `PpError` and without panicking".
//!
//! Self-skips loudly when the oracle headers are absent (mirrors the O2/O3 and
//! `oracle_bcc452` self-skip idiom), so the suite stays green on machines
//! without the BC45 CD.
//!
//! Mechanism: each header `FOO.H` is preprocessed as the one-line translation
//! unit `#include <FOO.H>\n` through a [`SearchPathResolver`] rooted at the
//! INCLUDE dir — exactly the `-I <INCLUDE>` driver path. Unknown nested system
//! headers fall back to the era-typical empty stub (so a header that pulls in
//! `<some_unmodelled.h>` is not penalised for the *include target*, only for
//! its own directives). `catch_unwind` quarantines any panic so one bad header
//! cannot abort the measurement.

#![cfg(windows)]

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use mdbcc::Lexer;
use mdbcc::pp::{self, DefaultResolver, IncludeResolver, SearchPathResolver};

/// Ratchet floor: the observed ACCEPT count at the time this harness landed
/// (116 / 246). `assert!(n_accept >= FLOOR_O15)` turns the metric into a
/// one-way gate — a regression that drops acceptance fails the build; progress
/// is recorded by raising this constant. S3 exit target is 246 (every header).
///
/// The 130 current REJECTs group into three actionable causes (printed by the
/// test): 94 are `#define NAME (body)` object-macros that the function-like
/// detector mis-reads as func-like because its adjacency check only requires
/// `(` to be *after* the name, not *immediately* after it; 23 are deliberate
/// `#error`s behind guards mdbcc does not yet satisfy (e.g. `__BORLANDC__`,
/// `__cplusplus`, Win-version macros); 13 are lexer-level (a trailing `0x1A`
/// DOS-EOF byte, or `stdarg.h`/`varargs.h` char-constant lexing). Each is a
/// distinct next-tick fix; this tick only measures.
// S3.2 raised this 116 → 208 by fixing function-like-macro detection
// (spaced object-macros `#define NAME (body)` were mis-parsed).
// S3.3 raised it 208 → 215 with a COUPLED fix: (a) lexer leniency — a lone
// `'` in directive free-text (`#error Can't ...`) now lexes as a stray
// pp-token instead of hard-failing the whole file (recovers the `<stdarg.h>`
// family); (b) the Borland bcc32 4.52 compiler-predefined macros
// (`__BORLANDC__`=0x0460, `__TURBOC__`, `__WIN32__`, `__FLAT__`, `__CONSOLE__`,
// `__TLS__`, `_Windows`) so the arch headers stop `#error`-ing behind
// `__BORLANDC__`/Win32 guards. Remaining 31 rejects: 21 deliberate
// `#error "Must use C++"` behind `!defined(__cplusplus)` (deferred — C++-mode
// only; enabling it flips `extern "C" {` blocks on) plus a few that need other
// macros (objbase.h-first, W32SUT_16/32, BGI-not-on-Windows).
// S3.4 raised it 215 → 225: the lexer now treats a token-start `0x1A`
// (Ctrl-Z) as logical DOS-EOF (Borland behaviour), recovering the ~10
// headers with a trailing Ctrl-Z.
// S3.5 raised it 225 → 241: this harness now preprocesses each header in
// **C++ mode** (`pp::preprocess(.., cplusplus = true)`), which predefines
// `__cplusplus` (= 1) and `__BCPLUSPLUS__` (= 0x0340) — both probed from
// bcc32 4.52 compiling a `.cpp` TU. That satisfies the `#if
// !defined(__cplusplus)` guard, so all 21 C++-only `#error "Must use C++"`
// headers now ACCEPT (their `extern "C" {` token blocks preprocess fine;
// parsing is a later tick). The compile path stays C mode, so the x64
// SipHash baselines are byte-identical.
// Remaining 5 REJECTs are NOT __cplusplus-related — they are headers that
// deliberately `#error` unless preprocessed in a richer context that the
// standalone `#include <FOO.H>` TU does not provide (and which bcc32 itself
// would error on the same way): GRAPHICS.H (BGI unsupported under Win32),
// INITGUID.H / MSACM.H (require objbase.h / MMREG.H included first),
// MAPIWIN.H (unknown DLL-suffix platform macro), W32SUT.H (needs
// W32SUT_16/W32SUT_32 from the includer). These are header-ordering /
// platform-context guards, not preprocessor gaps.
// Never regress.
const FLOOR_O15: usize = 241;

/// Outcome of preprocessing one header.
enum Outcome {
    /// Phase 4 produced tokens with no error and no panic.
    Accept,
    /// `pp::preprocess` (or the lexer) returned an error.
    Reject(String),
    /// Preprocessing panicked (caught via `catch_unwind`).
    Panic(String),
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn include_dir() -> PathBuf {
    repo_root().join("wrk_oracle\\bc452\\BC45\\INCLUDE")
}

/// Enumerate the `*.h` files directly in `dir` (non-recursive — the root set
/// is the 246 headers; `CLASSLIB/`, `SYS/`, `OWL/` etc. are reachable via
/// `#include` but are not themselves part of the top-level acceptance set).
fn list_headers(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read INCLUDE dir")
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if !path.is_file() {
                return None;
            }
            let name = e.file_name().to_str()?.to_string();
            // Case-insensitive `.h` (the headers are UPPERCASE `.H`).
            if name.to_ascii_lowercase().ends_with(".h") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names
}

/// Preprocess `#include <header>` through a SearchPathResolver rooted at
/// `dir`, catching panics. Returns the classified [`Outcome`].
fn preprocess_header(dir: &Path, header: &str) -> Outcome {
    let resolver = SearchPathResolver {
        dirs: vec![dir.to_path_buf()],
        fallback: DefaultResolver {
            base_dir: dir.to_path_buf(),
        },
    };
    // A tiny TU that includes the header by its (lowercased) name — the
    // resolver's case-insensitive search maps it back to the on-disk `.H`.
    let tu = format!("#include <{}>\n", header.to_ascii_lowercase());
    let result = panic::catch_unwind(AssertUnwindSafe(|| run_pp(&tu, header, &resolver)));
    match result {
        Ok(Ok(())) => Outcome::Accept,
        Ok(Err(msg)) => Outcome::Reject(msg),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic>".to_string());
            Outcome::Panic(msg)
        }
    }
}

/// Lex + preprocess `src` in **C++ mode**; map any error to its `Display`
/// string. C++ mode (`cplusplus = true`) predefines `__cplusplus` /
/// `__BCPLUSPLUS__` so the 21 headers gated behind `#if !defined(__cplusplus)`
/// (`#error "Must use C++"`) accept and their `extern "C" {` blocks switch on —
/// the whole point of this S3 tick. (The *compile* path stays C mode; only
/// this oracle measures C++-mode header acceptance.)
fn run_pp(src: &str, file: &str, resolver: &dyn IncludeResolver) -> Result<(), String> {
    let tokens = Lexer::tokenize(src.as_bytes()).map_err(|e| e.to_string())?;
    pp::preprocess(tokens, file, resolver, true)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Collapse a concrete preprocessor error into a coarse *cause* bucket so the
/// per-header failures group into an actionable gap list (the raw message
/// carries line/col/specifics; the bucket is the recurring shape).
fn cause_bucket(msg: &str) -> &'static str {
    let m = msg.to_ascii_lowercase();
    if m.contains("macro params") || m.contains("macro parameter") {
        "function-macro param list (e.g. `#define X (-1)` mis-read as func-like)"
    } else if m.contains("macro definition") || m.contains("#define expects") {
        "malformed #define"
    } else if m.contains("unterminated #if") {
        "unterminated conditional (#if without #endif)"
    } else if m.contains("#elif") || m.contains("#else") || m.contains("#endif") {
        "stray/mismatched conditional directive"
    } else if m.contains("unknown directive") {
        "unknown directive"
    } else if m.contains("cannot open include") {
        "missing include file (resolver miss)"
    } else if m.contains("#error") {
        "#error fired (likely a missing predefined macro guard, e.g. __BORLANDC__)"
    } else if m.contains("#if") && (m.contains("expression") || m.contains("value")) {
        "#if constant-expression evaluation"
    } else if m.contains("expected ')'") || m.contains("expected ','") {
        "expression/paren structure in directive"
    } else if m.contains("nested too deeply") {
        "include nested too deeply"
    } else if m.contains("argument") {
        "macro argument count/binding"
    } else {
        "other preprocessor error"
    }
}

#[test]
fn o15_header_acceptance() {
    let dir = include_dir();
    if !dir.is_dir() {
        println!(
            "[o15] SKIP: {} not present (self-skip; the BC45 INCLUDE tree is \
             not on this machine).",
            dir.display()
        );
        return;
    }

    let headers = list_headers(&dir);
    let total = headers.len();
    assert!(total > 0, "no .h headers found under {}", dir.display());

    let mut accept: Vec<String> = Vec::new();
    // (bucket, Vec<(header, raw message)>)
    let mut rejects: std::collections::BTreeMap<&'static str, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    let mut panics: Vec<(String, String)> = Vec::new();

    for header in &headers {
        match preprocess_header(&dir, header) {
            Outcome::Accept => accept.push(header.clone()),
            Outcome::Reject(msg) => {
                rejects
                    .entry(cause_bucket(&msg))
                    .or_default()
                    .push((header.clone(), msg));
            }
            Outcome::Panic(msg) => panics.push((header.clone(), msg)),
        }
    }

    let n_accept = accept.len();
    let n_reject: usize = rejects.values().map(|v| v.len()).sum();
    let n_panic = panics.len();

    // ---- report ----------------------------------------------------------
    println!("\n=== O15: Borland header preprocessor acceptance ===");
    println!("INCLUDE dir: {}", dir.display());
    println!("TOTAL {total}  |  ACCEPT {n_accept}  REJECT {n_reject}  PANIC {n_panic}\n");

    if !rejects.is_empty() {
        println!("--- REJECT, grouped by cause (the S3 gap list) ---");
        for (bucket, items) in &rejects {
            println!("[{}]  ({} header(s))", bucket, items.len());
            for (h, msg) in items {
                println!("    {h:<16} {msg}");
            }
        }
        println!();
    }
    if !panics.is_empty() {
        println!("--- PANIC ---");
        for (h, msg) in &panics {
            println!("    {h:<16} {msg}");
        }
        println!();
    }

    // A compact summary line that is easy to grep across runs.
    println!("ACCEPT {n_accept} / {total}  (FLOOR_O15 = {FLOOR_O15})");

    // ---- ratchet ---------------------------------------------------------
    assert!(
        n_accept >= FLOOR_O15,
        "O15 regression: only {n_accept} headers preprocess (floor is \
         {FLOOR_O15}). A change reduced preprocessor acceptance of the real \
         Borland headers."
    );
}
