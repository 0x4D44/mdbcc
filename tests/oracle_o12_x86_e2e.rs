//! O12 — e2e differential harness for the i386 (Win32) backend (S2-exit).
//!
//! This is the canonical S2-exit measurement: it runs the **88-program
//! portable corpus** — the hand-curated source per `tests/end_to_end.rs`
//! test, the same set locked byte-for-byte (x64) by
//! `tests/o1_byte_identity.rs` — through mdbcc's i386 backend, then compares
//! each program's exit code and stdout against the bcc32 + tlink32 reference
//! (the BCC 4.52 oracle). The S2-exit metric is "≥80/88 exits match bcc32 as
//! 32-bit"; this test enumerates exactly how many already match and groups
//! the remaining gaps by apparent cause so the next ticks are actionable.
//!
//! It deliberately mirrors `tests/oracle_o12_x86_corpus.rs` (the corpus
//! sibling): same per-fixture classify/compare logic, the same
//! `link_opts_i386`/`mdbcc_i386_pe` helpers, the same stdout runner, CRLF
//! folding and `BccOracle` diff, the same `catch_unwind` around compile+link.
//! The only structural difference is the input: this harness iterates an
//! **in-memory** `FIXTURES` table (inline source strings) rather than `*.c`
//! files on disk, because the canonical 88-program sources live as string
//! literals in `tests/end_to_end.rs` / `tests/o1_byte_identity.rs`.
//!
//! Per-fixture classification (identical to the corpus harness):
//!   - MATCH       — mdbcc built+ran it and its exit+stdout match bcc32.
//!   - MISMATCH    — mdbcc built+ran it but exit or stdout diverge from bcc32.
//!   - COMPILE-GAP — mdbcc's compile or link panicked / errored (unimplemented).
//!   - RUN-SKIP    — the mdbcc PE could not be spawned (environment issue).
//!   - REF-GAP     — bcc32 itself failed to build the fixture (reference fault).
//!
//! ## Fixture-list duplication (acknowledged, mirrors J-20b)
//!
//! `FIXTURES` below is a **verbatim copy** of the array in
//! `tests/o1_byte_identity.rs` (which is itself a hand-curated copy of the
//! canonical source per `tests/end_to_end.rs` test). The brief mandates this
//! copy: `o1_byte_identity.rs` is a hard regression lock (88 x64 SipHash
//! baselines) and must NOT be modified or depended upon by this test. These
//! are source-string literals, so a verbatim copy is exact. A `len()==88`
//! assertion below guards against silent drift of the copy.

#![cfg(windows)]

mod support;

use std::io::Read as _;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;

use support::bcc_oracle::{BccOracle, BuildOpts};

/// Ratchet floor for the **e2e** (88-program) set, separate from the corpus
/// harness's `FLOOR`. Set to the MATCH count observed after the i386
/// whole-struct copy was fixed (80/88). Of the 8 non-MATCH:
///
/// - 5 are **REF-GAP** (genuine bcc32 4.52 faults, not mdbcc gaps): the 3
///   inline-asm fixtures need tasm32.exe (absent on the CD);
///   `libc_strcpy_strcat_memcpy_memset` is rejected by bcc32's strict-C89
///   mid-block-declaration rule; `cxx_inheritance_destructor_chains_to_base`
///   is ill-formed C++ (derived touches Base's *private* member) that bcc32
///   correctly rejects.
/// - 1 is **COMPILE-GAP**: `self_referential_linked_list` panics in codegen —
///   a struct WITH a pointer member needs i386 4-byte pointers (sizeof(ptr)
///   is still 8/LLP64 on the x86 path). That is a SEPARATE, documented gap.
/// - 2 are **MISMATCH**: `sizeof_types` + `typedef_scalar_alias_and_sizeof_struct`
///   compute `sizeof(int*)`=8 (Win64) instead of 4 (Win32 ABI gap).
///
/// `whole_struct_assignment_copies` now MATCHes: the builtin record-assignment
/// arm (`b = a;`) shuffled the source/dest addresses through bare `mov reg64,
/// reg64`s, which have no x86 encoder row and panicked the Win32 encoder with
/// NoMatchingRow. Those three Movs are now width-aware (`wreg` ⇒ reg32 on
/// Win32, reg64 on Win64 — byte-identical to the historical emit); the
/// `emit_struct_copy` body was already REX-free byte moves.
///
/// The 4 RAII/destructor fixtures that previously crashed on i386
/// (0xC0000005) now MATCH: `emit_dtors` delivered `this` via the Win64
/// `lea rcx` (REX.W) + RCX-pass form unconditionally, so the i386 dtor read
/// an uninitialised `[ebp+8]`. On Win32 the scope-exit dtor is now a proper
/// cdecl call (`lea ecx,[ebp+disp]; push ecx; call ~Tag; add esp,4`).
///
/// **i386 ILP32 pointer size + byte alignment (this tick)** flipped the final
/// 3: `self_referential_linked_list` (a `struct N { int v; struct N *next; }`
/// — the pointer member now lays out at offset 4 with a 4-byte width, so
/// `p->next` reads the right slot), `sizeof_types` (`sizeof(int*)` folds to 4,
/// not 8), and `typedef_scalar_alias_and_sizeof_struct` (`struct { char c;
/// int i; }` is 5 bytes under bcc32 4.52's *default byte alignment* — mdbcc's
/// Win32 layout now caps field alignment at 1, matching). With those, the only
/// non-MATCH fixtures are the 5 genuine REF-GAPs, so this is the ceiling.
///
/// Raise this as i386 coverage grows; it must never regress (and never drop
/// below 80). The S2-exit *target* of >=80 is exceeded; 83 is the reachable
/// ceiling (the 5 REF-GAPs are bcc32 faults, not mdbcc gaps).
const FLOOR_E2E: usize = 83;

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Fold `\r\n` -> `\n`. mdbcc emits bytes verbatim via `WriteFile`; bcc32's
/// CRT translates `\n` -> `\r\n` in text mode on a pipe. Folding CRLF on both
/// sides compares the logical output, not the OS line discipline.
fn norm_eol(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Run a PE image with a 5 s timeout, capturing stdout. `Some((code, out))` on
/// clean exit; `None` if the spawn/write failed (environment issue — RUN-SKIP).
fn run_pe_capture(pe: &[u8], tag: &str) -> Option<(i32, Vec<u8>)> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "mdbcc_o12e2e_{tag}_{:x}.exe",
        std::process::id() as u64 * 0x1000 + Instant::now().elapsed().as_nanos() as u64,
    ));
    if std::fs::write(&path, pe).is_err() {
        return None;
    }
    let result = match Command::new(&path).stdout(Stdio::piped()).spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            let code = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(5) {
                            let _ = child.kill();
                            // A hang is a real defect, not an env skip — surface it.
                            panic!("{tag}: i386 PE hung (>5s)");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("{tag}: wait failed: {e}"),
                }
            };
            let mut buf = Vec::new();
            if let Some(mut so) = child.stdout.take() {
                let _ = so.read_to_end(&mut buf);
            }
            code.map(|c| (c, buf))
        }
        Err(_) => None,
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// Compile + link `src` through mdbcc's i386 backend, returning the PE bytes.
/// Returns `Err` on a compile or link failure; panics propagate to the
/// caller's `catch_unwind` (the encoder `panic!`s on unimplemented
/// constructs). mdbcc parses the C++ subset regardless of extension, so a
/// single entry point covers both C and C++ fixtures.
fn mdbcc_i386_pe(src: &[u8], file_name: &str) -> Result<Vec<u8>, String> {
    // No `#include` resolution is required by the 88 (the few `#include`d
    // headers are stubbed internally), so a base dir of the manifest root is
    // sufficient and matches the corpus harness's resolver shape.
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver = DefaultResolver { base_dir };
    let obj = compile_to_object_with_target(src, file_name, &resolver, TargetKind::Win32)
        .map_err(|e| format!("compile: {e:?}"))?;
    link::link(&[Input::Object(&obj)], &link_opts_i386()).map_err(|e| format!("link: {e:?}"))
}

/// Per-fixture outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Match,
    Mismatch,
    CompileGap,
    RunSkip,
    RefGap,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Match => "MATCH",
            Status::Mismatch => "MISMATCH",
            Status::CompileGap => "COMPILE-GAP",
            Status::RunSkip => "RUN-SKIP",
            Status::RefGap => "REF-GAP",
        }
    }
}

/// C-vs-C++ detection for an inline source — the **token fast path**.
///
/// These 88 sources are string literals (no file extension to key off), so we
/// must infer the language. This token classifier flags a fixture as C++ iff
/// its source contains a token that is **illegal or meaningless in C89/C99** —
/// i.e. a token bcc32 would reject when handed a `.c` file:
///
/// - `class ` / `class\t` (class definitions)
/// - `::` (scope resolution: out-of-line defs, member-init, `operator`)
/// - `new ` / `delete ` (operator new / delete)
/// - `operator` (operator overloading)
/// - `public:` / `private:` / `protected:` (access specifiers)
/// - `this->` / `this ` (the implicit `this`)
/// - `&` used as a *reference declarator* (`int& `, `int &`, `& r`, …)
/// - a C++ **default argument** (`= <value>)` in a param list — see
///   [`has_default_arg`]).
///
/// It does NOT, and cannot cheaply, catch C++ that is *syntactically valid C*
/// but semantically illegal — namely **function overloading** (two same-named
/// functions). Three fixtures fall here (`cxx_overload_by_param_type`,
/// `cxx_overload_by_arity`, `cxx_overload_pointer_vs_int`); a token scan can't
/// distinguish them from a legal C prototype-then-definition pair (e.g.
/// `prototype_then_definition_links`). Those are resolved by the **runtime
/// probe** in [`reference_build`]: build as C, and if bcc32 produces no exe,
/// rebuild as C++ (exactly the brief's "if it fails to compile as C, build as
/// C++" rule). So the overall rule is: *token-C++ ⇒ C++; otherwise try C, fall
/// back to C++ on a build failure.*
///
/// mdbcc itself is language-agnostic (parses the C++ subset regardless of
/// extension), so `lang` only steers the **bcc32** reference side.
///
/// The token classifier flags exactly the 23 token-visible `cxx_*` fixtures as
/// C++ and everything else (incl. the 3 overload fixtures) as C — verified by
/// `lang_detection_matches_cxx_prefix`. It is purely content-driven; the
/// `cxx_` names are never consulted.
fn detect_lang(src: &str) -> support::bcc_oracle::Lang {
    let cpp = src.contains("class ")
        || src.contains("class\t")
        || src.contains("::")
        || src.contains("new ")
        || src.contains("delete ")
        || src.contains("operator")
        || src.contains("public:")
        || src.contains("private:")
        || src.contains("protected:")
        || src.contains("this->")
        || src.contains("this ")
        // reference declarators / parameters (illegal in C):
        || src.contains("int& ")
        || src.contains("int &")
        || src.contains("& r")
        || src.contains("&r ")
        || src.contains("& o")
        || src.contains("& v")
        || src.contains("&v,")
        // C++ default arguments: an `= <value>` immediately before the `)`
        // that closes a parameter list (illegal in C). Detected structurally
        // so it does not fire on enum initialisers (`GREEN = 5,` — terminated
        // by a comma, valid C) or ordinary assignments.
        || has_default_arg(src);
    if cpp {
        support::bcc_oracle::Lang::Cpp
    } else {
        support::bcc_oracle::Lang::C
    }
}

/// Structural detector for a C++ default-argument: scans for a parameter
/// declaration of the form `<type> <name> = <value>` where `<value>` is the
/// last thing before a `)` or `,` (the close/next of a parameter list). This
/// is precisely the shape of `int h = 3)`, `int v = 100)`, `int add = 1)` and
/// is illegal in C.
///
/// The `<type>`-keyword requirement before the `<name> =` is what
/// distinguishes a *default argument* from an ordinary assignment that
/// happens to end in `)`. The motivating false positives without it were the
/// `for`-loop increment `i = i + 1)` and a `for`-cond — both are assignments
/// to an already-declared variable (no leading type), so they are correctly
/// rejected. It also does not match `GREEN = 5,` (enum: no type before the
/// name) nor `if (a == b)` (`==`, no initialiser).
fn has_default_arg(src: &str) -> bool {
    const TYPES: &[&str] = &[
        "int", "char", "long", "short", "unsigned", "signed", "float", "double", "void",
    ];
    let bytes = src.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        // A single '=' opening an initialiser (not ==, <=, >=, !=, +=, …).
        let is_init_eq = bytes[i] == b'='
            && bytes[i + 1] != b'='
            && (i == 0
                || !matches!(
                    bytes[i - 1],
                    b'=' | b'<'
                        | b'>'
                        | b'!'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'/'
                        | b'%'
                        | b'&'
                        | b'|'
                        | b'^'
                ));
        if !is_init_eq {
            i += 1;
            continue;
        }

        // (1) Value run must reach ')' or ',' before ';'/'{'/'}'/'(' — i.e.
        //     it sits inside a parameter list.
        let mut j = i + 1;
        let mut saw_value = false;
        let mut in_param_list = false;
        while j < bytes.len() {
            match bytes[j] {
                b')' | b',' if saw_value => {
                    in_param_list = true;
                    break;
                }
                b';' | b'{' | b'}' | b'(' => break,
                b' ' | b'\t' | b'\r' | b'\n' => {}
                _ => saw_value = true,
            }
            j += 1;
        }
        if !in_param_list {
            i += 1;
            continue;
        }

        // (2) Walk left over whitespace, then the LHS identifier, then more
        //     whitespace, and require a type keyword immediately before it.
        let mut k = i; // points at '='
        let back_ws = |k: &mut usize| {
            while *k > 0 && matches!(bytes[*k - 1], b' ' | b'\t' | b'\r' | b'\n') {
                *k -= 1;
            }
        };
        back_ws(&mut k);
        // Skip the LHS identifier.
        let id_end = k;
        while k > 0 && (bytes[k - 1].is_ascii_alphanumeric() || bytes[k - 1] == b'_') {
            k -= 1;
        }
        if k == id_end {
            i += 1; // no identifier before '=' — not a declaration.
            continue;
        }
        back_ws(&mut k);
        // The token now ending at k is the (possibly last) type word.
        let type_end = k;
        while k > 0 && (bytes[k - 1].is_ascii_alphanumeric() || bytes[k - 1] == b'_') {
            k -= 1;
        }
        let word = &src[k..type_end];
        if TYPES.contains(&word) {
            return true;
        }
        i += 1;
    }
    false
}

/// A short "apparent cause" bucket for COMPILE-GAP / MISMATCH / REF-GAP so the
/// printed report is actionable (groups gaps by the construct the next tick
/// must implement, or by the reference-side fault). Derived from the fixture
/// name + the error/divergence note. The buckets below were verified against
/// the actual bcc32 diagnostics / mdbcc errors at authoring time (see the
/// task report); they describe *why* each fixture is not a MATCH.
fn cause_bucket(name: &str, note: &str) -> &'static str {
    let n = note.to_ascii_lowercase();

    // ---- mdbcc i386 codegen gaps (COMPILE-GAP) ----
    // The S2b.5-scope reference-parameter gap: `int&`/`Cls&` params aren't
    // lowered on i386 yet. Covers the two reference fixtures AND the three
    // operator overloads (which take a `Cls&` operand).
    if n.contains("reference-parameter") {
        return "i386: reference-param call (S2b.5)";
    }
    if n.contains("nomatchingrow") {
        return "i386: encoder NoMatchingRow";
    }
    if n.contains("movsd") || n.contains("xmm") || (n.contains("float") && n.contains("compile")) {
        return "i386: float/SSE";
    }
    if n.contains("panic in codegen") {
        // Both remaining panics are struct value/pointer handling on i386
        // (whole-struct copy `b = a`; self-referential `p = p->next` + `+=`).
        return "i386: struct copy / self-ref pointer codegen (panic)";
    }

    // ---- mdbcc i386 runtime divergences (MISMATCH) ----
    // RAII / destructor ordering crashes: mdbcc faults (0xC0000005 =
    // -1073741819) where bcc32 returns the computed value.
    if n.contains("1073741819") || n.contains("c0000005") {
        return "i386: RAII/dtor crash (0xC0000005)";
    }
    // `sizeof(int*)` is 8 (Win64 default) on the i386 path instead of 4 — an
    // ABI gap. `sizeof_types` (13 vs 9) and `typedef…sizeof_struct` both hit
    // it (pointer/struct-layout sizing).
    if name.contains("sizeof") || name == "typedef_scalar_alias_and_sizeof_struct" {
        return "i386: sizeof(ptr) ABI (8 vs 4)";
    }

    // ---- reference-side faults (REF-GAP), confirmed genuine ----
    // bcc32 4.52 needs tasm32.exe (absent on the CD) for inline asm.
    if name.contains("asm") {
        return "REF: bcc32 needs tasm32 for inline asm";
    }
    // bcc32 4.52 (strict C89) rejects mid-block declarations.
    if name.starts_with("libc_") {
        return "REF: bcc32 C89 mid-block decl rejected";
    }
    // bcc32 enforces private base-member access (derived touches Base's
    // private `log`); ill-formed C++ that mdbcc accepts.
    if name.contains("inherit") {
        return "REF: bcc32 private base-member access";
    }

    "other"
}

/// Short divergence note for a MISMATCH (first differing line, or the exits).
fn divergence(mdbcc_exit: i32, mdbcc_out: &[u8], bcc_exit: Option<i32>, bcc_out: &[u8]) -> String {
    if Some(mdbcc_exit) != bcc_exit {
        return format!("exit mdbcc={mdbcc_exit} bcc={bcc_exit:?}");
    }
    let m = String::from_utf8_lossy(mdbcc_out);
    let b = String::from_utf8_lossy(bcc_out);
    for (i, (ml, bl)) in m.lines().zip(b.lines()).enumerate() {
        if ml != bl {
            return format!("stdout line {}: mdbcc={ml:?} bcc={bl:?}", i + 1);
        }
    }
    format!(
        "stdout length: mdbcc={} bytes, bcc={} bytes",
        mdbcc_out.len(),
        bcc_out.len()
    )
}

/// Build `src` with the bcc32 reference, resolving the language per the
/// rule documented on [`detect_lang`]: use the token classifier first; if it
/// says C but bcc32 then produces no exe, rebuild as C++ (the "fails as C ⇒
/// C++" fallback that catches token-invisible overloading). Returns the built
/// exe path (if any) and the language actually used (for the report).
fn reference_build(oracle: &BccOracle, src: &str) -> (Option<PathBuf>, support::bcc_oracle::Lang) {
    use support::bcc_oracle::Lang;
    let lang = detect_lang(src);
    let r = oracle.build(
        src,
        &BuildOpts {
            lang,
            ..BuildOpts::default()
        },
    );
    if r.exe.is_some() || lang == Lang::Cpp {
        return (r.exe, lang);
    }
    // Token-C but bcc32 rejected it as C — retry as C++ (overload fixtures).
    let r2 = oracle.build(
        src,
        &BuildOpts {
            lang: Lang::Cpp,
            ..BuildOpts::default()
        },
    );
    (r2.exe, Lang::Cpp)
}

#[test]
fn o12_x86_e2e_differential() {
    let Some(oracle) = BccOracle::discover() else {
        eprintln!("SKIP: bcc32 oracle absent");
        return;
    };

    // Guard against silent drift of the verbatim copy below.
    assert_eq!(
        FIXTURES.len(),
        88,
        "FIXTURES drifted from the 88-program e2e set; re-copy from \
         tests/o1_byte_identity.rs (do NOT modify that file)."
    );

    // Suppress the encoder's noisy panic backtrace for the duration: the
    // catch_unwind below converts a panic into COMPILE-GAP, so the backtrace
    // is pure noise that would bury the status table. Restore afterwards.
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut results: Vec<(String, Status, String)> = Vec::new();

    for (name, src) in FIXTURES {
        let name = name.to_string();
        let src_bytes = src.as_bytes();
        let file_name = format!("{name}.c");

        // (a) compile + link via mdbcc, catching the encoder's panics.
        let built = panic::catch_unwind(AssertUnwindSafe(|| mdbcc_i386_pe(src_bytes, &file_name)));
        let pe = match built {
            Ok(Ok(pe)) => pe,
            Ok(Err(why)) => {
                results.push((name, Status::CompileGap, why));
                continue;
            }
            Err(_) => {
                results.push((name, Status::CompileGap, "panic in codegen".into()));
                continue;
            }
        };

        // (b) run the mdbcc PE, capturing exit + stdout.
        let run = panic::catch_unwind(AssertUnwindSafe(|| run_pe_capture(&pe, &name)));
        let (mdbcc_exit, mdbcc_out) = match run {
            Ok(Some((code, out))) => (code, norm_eol(&out)),
            Ok(None) => {
                results.push((name, Status::RunSkip, "spawn/write failed".into()));
                continue;
            }
            Err(_) => {
                // run_pe_capture panics only on hang/wait-error: a real defect.
                results.push((
                    name,
                    Status::Mismatch,
                    "mdbcc PE hung or wait failed".into(),
                ));
                continue;
            }
        };

        // (c) build the same source with bcc32 (reference). Resolve C vs C++
        // from the source content (these are inline sources with no `.c`/.cpp
        // extension and no `// oracle:` directive), with a C->C++ fallback for
        // token-invisible overloading — see `reference_build`/`detect_lang`.
        // mdbcc itself parses the C++ subset regardless of extension.
        let (bcc_exe, _lang) = reference_build(&oracle, src);
        let Some(bcc_exe) = bcc_exe else {
            results.push((name, Status::RefGap, "bcc32 build produced no exe".into()));
            continue;
        };
        let bcc_run = oracle.run(&bcc_exe, &[]);
        let bcc_exit = bcc_run.output.exit;
        let bcc_out = norm_eol(&bcc_run.output.stdout);

        // (d) compare exit + stdout.
        if Some(mdbcc_exit) == bcc_exit && mdbcc_out == bcc_out {
            results.push((name, Status::Match, String::new()));
        } else {
            let note = divergence(mdbcc_exit, &mdbcc_out, bcc_exit, &bcc_out);
            results.push((name, Status::Mismatch, note));
        }
    }

    panic::set_hook(prev_hook);

    // ---- report -------------------------------------------------------------
    let mut n_match = 0usize;
    let mut n_mismatch = 0usize;
    let mut n_compile_gap = 0usize;
    let mut n_run_skip = 0usize;
    let mut n_ref_gap = 0usize;

    eprintln!("\n=== O12 i386 e2e differential (88-program S2-exit set) ===");
    for (name, status, note) in &results {
        match status {
            Status::Match => n_match += 1,
            Status::Mismatch => n_mismatch += 1,
            Status::CompileGap => n_compile_gap += 1,
            Status::RunSkip => n_run_skip += 1,
            Status::RefGap => n_ref_gap += 1,
        }
        if note.is_empty() {
            eprintln!("  {:<14} {name}", status.label());
        } else {
            eprintln!("  {:<14} {name}  ({note})", status.label());
        }
    }
    let compiled_and_run = n_match + n_mismatch;
    eprintln!(
        "\nMATCH {n_match} / 88 ; compiled-and-run {compiled_and_run} ; \
         MISMATCH {n_mismatch} ; COMPILE-GAP {n_compile_gap} ; \
         RUN-SKIP {n_run_skip} ; REF-GAP {n_ref_gap}",
    );

    // ---- actionable gap list: group COMPILE-GAP/MISMATCH by apparent cause --
    let mut buckets: std::collections::BTreeMap<&str, Vec<String>> =
        std::collections::BTreeMap::new();
    for (name, status, note) in &results {
        if matches!(
            status,
            Status::CompileGap | Status::Mismatch | Status::RefGap
        ) {
            let label = match status {
                Status::CompileGap => "COMPILE-GAP",
                Status::Mismatch => "MISMATCH",
                Status::RefGap => "REF-GAP",
                _ => unreachable!(),
            };
            let bucket = cause_bucket(name, note);
            buckets
                .entry(bucket)
                .or_default()
                .push(format!("{label} {name}"));
        }
    }
    if !buckets.is_empty() {
        eprintln!("\n--- gaps grouped by apparent cause (S2 actionable list) ---");
        for (cause, members) in &buckets {
            eprintln!("  [{cause}]  ({} fixtures)", members.len());
            for m in members {
                eprintln!("      {m}");
            }
        }
    }

    // ---- ratchet ------------------------------------------------------------
    // Green now; a floor for future work. Raise FLOOR_E2E as i386 coverage
    // grows; it must never regress. We deliberately do NOT assert >=80 (the
    // S2-exit target) — most remaining fixtures are known gaps.
    assert!(
        n_match >= FLOOR_E2E,
        "i386 e2e MATCH count regressed: {n_match} < floor {FLOOR_E2E}"
    );
}

/// Pins the **token** classifier `detect_lang` so a future edit that breaks
/// the inference is caught here, not as a flood of REF-GAPs in the diff run.
///
/// Expectation: every token-visible C++ fixture (the `cxx_*` set *minus* the
/// three overload fixtures, whose C++-ness is invisible to a token scan) is
/// classified C++; every C fixture (and the three overload fixtures, handled
/// by the runtime C->C++ probe in `reference_build`) is classified C. The
/// `cxx_` names are used only to derive the *expected* answer here;
/// `detect_lang` itself never consults the name.
#[test]
fn lang_detection_matches_cxx_prefix() {
    use support::bcc_oracle::Lang;
    // The three fixtures that are valid C *syntax* (only illegal as C because
    // of function overloading) — invisible to a token scan, resolved by the
    // runtime probe instead.
    const TOKEN_INVISIBLE_CPP: &[&str] = &[
        "cxx_overload_by_param_type",
        "cxx_overload_by_arity",
        "cxx_overload_pointer_vs_int",
    ];
    for (name, src) in FIXTURES {
        let got = detect_lang(src);
        let want = if name.starts_with("cxx_") && !TOKEN_INVISIBLE_CPP.contains(name) {
            Lang::Cpp
        } else {
            Lang::C
        };
        assert_eq!(
            got, want,
            "detect_lang misclassified {name:?}: got {got:?}, want {want:?}"
        );
    }
}

// ===========================================================================
// FIXTURES: a VERBATIM copy of the array in `tests/o1_byte_identity.rs`
// (which is itself the hand-curated canonical source per `tests/end_to_end.rs`
// test — the 88-program set). Do NOT modify `tests/o1_byte_identity.rs`; this
// copy exists so this test does not depend on that hard regression lock.
// Keep in lockstep if the 88 ever change (the len()==88 assertion guards it).
// ===========================================================================

#[rustfmt::skip]
const FIXTURES: &[(&str, &str)] = &[
    ("returns_constant",
        "int main(void) { return 42; }"),
    ("arithmetic_precedence_and_parens",
        "int main(void) { return (2 + 3) * 8 - 10; }"),
    ("division_and_modulo",
        "int main(void) { return 17 / 5; }"),
    ("unary_operators",
        "int main(void) { return ~0; }"),
    ("negative_result_is_dword_exit_code",
        "int main(void) { return 3 - 10; }"),
    ("comparison_and_bitwise_operators",
        "int main(void) { return 3 < 5; }"),
    ("short_circuit_logical_operators",
        "int main(void) { return 1 && 2; }"),
    ("locals_and_assignment",
        "int main(void){ int a; int b; a = 6; b = 7; return a * b; }"),
    ("if_else_control_flow",
        "int main(void){ int x; x = 10; \
                if (x > 5) x = 100; else x = 200; return x; }"),
    ("while_loop_sum_1_to_100",
        "int main(void){ int i; int s; i = 1; s = 0; \
                while (i <= 100) { s = s + i; i = i + 1; } return s; }"),
    ("for_loop_factorial",
        "int main(void){ int f; int i; f = 1; \
                for (i = 1; i <= 5; i = i + 1) f = f * i; return f; }"),
    ("euclid_gcd",
        "int main(void){ int a; int b; int t; a = 48; b = 18; \
                while (b != 0) { t = b; b = a % b; a = t; } return a; }"),
    ("nested_loops_and_blocks",
        "int main(void){ int s; int i; int j; s = 0; \
                for (i = 1; i <= 3; i = i + 1) { \
                  for (j = 1; j <= 3; j = j + 1) { s = s + i * j; } } \
                return s; }"),
    ("fall_through_returns_zero",
        "int main(void){ int x; x = 1; }"),
    ("simple_function_call",
        "int add(int a, int b) { return a + b; } \
                int main(void) { return add(40, 2); }"),
    ("four_argument_function",
        "int f(int a, int b, int c, int d) { return a*1000 + b*100 + c*10 + d; } \
                int main(void) { return f(1, 2, 3, 4); }"),
    ("recursive_factorial",
        "int fact(int n) { if (n <= 1) return 1; return n * fact(n - 1); } \
                int main(void) { return fact(7); }"),
    ("recursive_fibonacci",
        "int fib(int n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } \
                int main(void) { return fib(15); }"),
    ("mutual_recursion_is_even",
        "int is_odd(int n) { if (n == 0) return 0; return is_even(n - 1); } \
                int is_even(int n) { if (n == 0) return 1; return is_odd(n - 1); } \
                int main(void) { return is_even(10) * 10 + is_odd(7); }"),
    ("cxx_reference_parameter_mutates_caller",
        "void inc(int& r) { r = r + 1; } \
               int main(void) { int a; a = 41; inc(a); return a; }"),
    ("cxx_reference_local_alias",
        "int main(void) { int a; int& r = a; a = 5; r = r * 8; return a; }"),
    ("cxx_reference_to_struct_member",
        "struct P { int x; int y; }; \
               void bump(int& v) { v = v + 10; } \
               int main(void) { P p; p.x = 1; p.y = 2; \
                 bump(p.x); bump(p.y); return p.x*100 + p.y; }"),
    ("cxx_class_ctor_and_methods",
        "class Counter { \
                 int n; \
               public: \
                 Counter(int s) { n = s; } \
                 void add(int d) { n = n + d; } \
                 int get() { return n; } \
               }; \
               int main(void) { Counter c(40); c.add(2); return c.get(); }"),
    ("cxx_method_via_pointer_and_this",
        "struct Point { \
                 int x; int y; \
                 void set(int a, int b) { x = a; y = b; } \
                 int sum() { return this->x + y; } \
               }; \
               int main(void) { Point p; Point *q; q = &p; \
                 q->set(30, 12); return q->sum(); }"),
    ("cxx_default_ctor_and_sibling_call",
        "class Acc { \
                 int t; \
               public: \
                 Acc() { t = 0; } \
                 void one() { t = t + 1; } \
                 int run() { one(); one(); one(); return t; } \
               }; \
               int main(void) { Acc a; return a.run(); }"),
    ("cxx_new_delete_scalar",
        "int main(void) { int* p = new int; *p = 42; \
                 int r = *p; delete p; return r; }"),
    ("cxx_new_class_ctor_and_method",
        "class Box { \
                 int v; \
               public: \
                 Box(int s) { v = s; } \
                 void add(int d) { v = v + d; } \
                 int get() { return v; } \
               }; \
               int main(void) { Box* b = new Box(40); \
                 b->add(2); int r = b->get(); delete b; return r; }"),
    ("cxx_new_runs_ctor_delete_runs_dtor",
        "class Res { \
                 int* slot; \
               public: \
                 Res(int* s) { slot = s; *slot = 1; } \
                 ~Res() { *slot = 99; } \
               }; \
               int main(void) { int v; v = 0; \
                 Res* r = new Res(&v); \
                 if (v != 1) return 7; \
                 delete r; \
                 return v; }"),
    ("cxx_raii_block_scope_reverse_order",
        "class Tr { \
                 int* log; int id; \
               public: \
                 Tr(int* L, int i) { log = L; id = i; } \
                 ~Tr() { *log = *log * 10 + id; } \
               }; \
               int main(void) { int v; v = 0; \
                 { Tr a(&v, 1); Tr b(&v, 2); } \
                 return v; }"),
    ("cxx_raii_destructor_runs_before_return",
        "class S { \
                 int* p; \
               public: \
                 S(int* q) { p = q; } \
                 ~S() { *p = *p + 7; } \
               }; \
               int bump(int* p) { S s(p); if (*p > 0) return 1; return 2; } \
               int main(void) { int v; v = 3; bump(&v); return v; }"),
    ("cxx_raii_inner_block_destructs_early",
        "class M { \
                 int* p; \
               public: \
                 M(int* q) { p = q; } \
                 ~M() { *p = *p + 1; } \
               }; \
               int main(void) { int v; v = 0; \
                 { M m(&v); } \
                 int w; w = v * 10; \
                 return w + v; }"),
    ("cxx_out_of_line_methods_header_style",
        "class Counter { \
                 int n; \
               public: \
                 Counter(int s); \
                 void add(int d); \
                 int get(); \
               }; \
               Counter::Counter(int s) { n = s; } \
               void Counter::add(int d) { n = n + d; } \
               int Counter::get() { return n; } \
               int main(void) { Counter c(40); c.add(2); return c.get(); }"),
    ("cxx_out_of_line_ctor_dtor_sibling_call",
        "class Acc { \
                 int t; int* sink; \
               public: \
                 Acc(int* s); \
                 void one(); \
                 int run(); \
                 ~Acc(); \
               }; \
               Acc::Acc(int* s) { t = 0; sink = s; } \
               void Acc::one() { t = t + 1; } \
               int Acc::run() { one(); one(); one(); return t; } \
               Acc::~Acc() { *sink = t * 7; } \
               int main(void) { int v; v = 0; \
                 { Acc a(&v); int r = a.run(); } \
                 return v; }"),
    ("cxx_operator_equality_member",
        "class Pt { \
                 int x; int y; \
               public: \
                 Pt(int a, int b) { x = a; y = b; } \
                 int operator==(Pt& o) { return x == o.x && y == o.y; } \
               }; \
               int main(void) { Pt a(3,4); Pt b(3,4); Pt c(3,9); \
                 int r = 0; \
                 if (a == b) r = r + 10; \
                 if (a == c) r = r + 1; \
                 return r; }"),
    ("cxx_operator_plus_out_of_line",
        "class Money { \
                 int cents; \
               public: \
                 Money(int c); \
                 int operator+(Money& o); \
               }; \
               Money::Money(int c) { cents = c; } \
               int Money::operator+(Money& o) { return cents + o.cents; } \
               int main(void) { Money a(150); Money b(75); return a + b; }"),
    ("cxx_operator_less_and_minus",
        "class N { \
                 int v; \
               public: \
                 N(int x) { v = x; } \
                 int operator<(N& o) { return v < o.v; } \
                 int operator-(N& o) { return v - o.v; } \
               }; \
               int main(void) { N a(7); N b(10); \
                 int r = 0; \
                 if (a < b) r = b - a; \
                 return r; }"),
    ("cxx_inheritance_members_and_methods",
        "class Base { \
               protected: \
                 int b; \
               public: \
                 Base() { b = 100; } \
                 int getB() { return b; } \
               }; \
               class Derived : public Base { \
                 int d; \
               public: \
                 Derived() { d = 7; } \
                 int sum() { return getB() + d; } \
               }; \
               int main(void) { Derived x; return x.sum(); }"),
    ("cxx_inheritance_meminit_base_args",
        "class Animal { \
                 int legs; \
               public: \
                 Animal(int n) { legs = n; } \
                 int numLegs() { return legs; } \
               }; \
               class Dog : public Animal { \
                 int tailWags; \
               public: \
                 Dog(int w) : Animal(4) { tailWags = w; } \
                 int score() { return numLegs() * 10 + tailWags; } \
               }; \
               int main(void) { Dog d(3); \
                 return d.numLegs() + d.score(); }"),
    ("cxx_inheritance_destructor_chains_to_base",
        "class Res { \
                 int* log; \
               public: \
                 Res(int* L) { log = L; *log = 1; } \
                 ~Res() { *log = *log * 2; } \
               }; \
               class Mgr : public Res { \
               public: \
                 Mgr(int* L) : Res(L) { *log = *log + 4; } \
                 ~Mgr() { *log = *log + 10; } \
               }; \
               int main(void) { int v; v = 0; \
                 { Mgr m(&v); } \
                 return v; }"),
    ("cxx_default_args_free_function",
        "int area(int w, int h = 3); \
               int area(int w, int h) { return w * h; } \
               int main(void) { return area(4) + area(5, 2); }"),
    ("cxx_default_args_member_and_ctor",
        "class Rect { \
                 int w; int h; \
               public: \
                 Rect(int a, int b = 5) { w = a; h = b; } \
                 int scale(int f = 2) { return w * h * f; } \
               }; \
               int main(void) { Rect r(4); Rect s(3, 10); \
                 return r.scale() + s.scale(1); }"),
    ("cxx_default_args_prototype_then_out_of_line",
        "class C { \
                 int n; \
               public: \
                 C(int v = 100); \
                 int get(int add = 1); \
               }; \
               C::C(int v) { n = v; } \
               int C::get(int add) { return n + add; } \
               int main(void) { C a; C b(7); return a.get() + b.get(5); }"),
    ("cxx_overload_by_param_type",
        "int f(int x) { return x + 1; } \
               int f(char* s) { return 100; } \
               int main(void) { return f(41) + f(\"hi\"); }"),
    ("cxx_overload_by_arity",
        "int g(int a, int b) { return a * b; } \
               int g(int a) { return a + 7; } \
               int main(void) { return g(6, 7) + g(10); }"),
    ("cxx_overload_pointer_vs_int",
        "int kind(int* p) { return 1; } \
               int kind(int v) { return 2; } \
               int main(void) { int x; x = 5; int* q; q = &x; \
                 return kind(q) * 10 + kind(x); }"),
    ("printf_decimal_and_text",
        "int main(void){ printf(\"x=%d y=%d\\n\", -7, 13); return 0; }"),
    ("printf_string_char_hex_unsigned",
        "int main(void){ \
           printf(\"%s!\\n\", \"hi\"); \
           printf(\"%c%c\\n\", 65, 66); \
           printf(\"%x %X\\n\", 255, 255); \
           printf(\"%u\\n\", -1); \
           printf(\"100%% done\\n\"); \
           return 0; }"),
    ("printf_returns_total_bytes_with_format",
        "int main(void){ return printf(\"v=%d\", 255); }"),
    ("printf_loop_and_expression_args",
        "int main(void){ int i; \
           for (i = 1; i <= 3; i = i + 1) printf(\"sq(%d)=%d\\n\", i, i*i); \
           return 0; }"),
    ("libc_strlen_strcmp_abs_atoi",
        "int main(void){ int r = 0; \
                 r = r + strlen(\"hello\"); \
                 if (strcmp(\"abc\", \"abc\") == 0) r = r + 10; \
                 if (strcmp(\"abc\", \"abd\") < 0) r = r + 20; \
                 r = r + abs(-13); \
                 r = r + atoi(\"100\"); \
                 r = r - atoi(\"-8\"); \
                 return r; }"),
    ("libc_strcpy_strcat_memcpy_memset",
        "int main(void){ \
                 char buf[32]; \
                 strcpy(buf, \"Hello\"); \
                 strcat(buf, \", \"); \
                 strcat(buf, \"world\"); \
                 printf(\"%s\\n\", buf); \
                 char dst[8]; \
                 memcpy(dst, \"abcd\", 5); \
                 printf(\"[%s]\\n\", dst); \
                 char fill[6]; \
                 memset(fill, 65, 5); \
                 fill[5] = 0; \
                 printf(\"%s\\n\", fill); \
                 return 0; }"),
    ("libc_respects_include_string_h_stub",
        "#include <string.h>\n\
               int main(void){ return strlen(\"abcdef\"); }"),
    ("inline_asm_block_is_dropped",
        "int main(void){ int x; x = 10; \
                 asm { mov eax, 99 } \
                 x = x + 5; return x; }"),
    ("inline_asm_statement_forms",
        "int main(void){ int r; r = 7; \
                 asm mov ax, bx; \
                 asm nop\n\
                 r = r * 6; return r; }"),
    ("inline_asm_underscore_and_paren_forms",
        "int main(void){ int v; v = 3; \
                 __asm { push eax\n pop eax } \
                 asm(\"nop\"); \
                 v = v + 39; return v; }"),
    ("struct_members_read_write",
        "struct P { int x; int y; }; \
               int main(void){ struct P p; p.x = 30; p.y = 12; return p.x + p.y; }"),
    ("struct_pointer_arrow_and_param",
        "struct P { int a; int b; }; \
               int sum(struct P *p){ return p->a + p->b; } \
               int main(void){ struct P q; q.a = 40; q.b = 2; return sum(&q); }"),
    ("self_referential_linked_list",
        "struct N { int v; struct N *next; }; \
               int main(void){ \
                 struct N a; struct N b; struct N c; \
                 a.v = 1; b.v = 2; c.v = 3; \
                 a.next = &b; b.next = &c; c.next = 0; \
                 int sum; struct N *p; sum = 0; p = &a; \
                 while (p) { sum += p->v; p = p->next; } \
                 return sum; }"),
    ("whole_struct_assignment_copies",
        "struct P { int x; int y; }; \
               int main(void){ struct P a; struct P b; \
                 a.x = 3; a.y = 4; b = a; b.x = 10; \
                 return a.x*100 + a.y*10 + b.x; }"),
    ("nested_structs",
        "struct Inner { int n; }; \
               struct Outer { struct Inner in; int k; }; \
               int main(void){ struct Outer o; o.in.n = 7; o.k = 35; \
                 return o.in.n + o.k; }"),
    ("array_of_structs",
        "struct V { int x; }; \
               int main(void){ struct V a[3]; int i; \
                 for (i = 0; i < 3; i++) a[i].x = i * i; \
                 return a[0].x + a[1].x + a[2].x; }"),
    ("union_overlaps_members",
        "union U { int i; char c[4]; }; \
               int main(void){ union U u; u.i = 0; u.c[0] = 65; return u.i; }"),
    ("enum_constants_are_values",
        "enum Color { RED, GREEN = 5, BLUE }; \
               int main(void){ return RED*100 + GREEN*10 + BLUE; }"),
    ("typedef_struct_alias",
        "typedef struct { int a; int b; } Pair; \
               int add(Pair *p){ return p->a + p->b; } \
               int main(void){ Pair q; q.a = 19; q.b = 23; return add(&q); }"),
    ("typedef_scalar_alias_and_sizeof_struct",
        "typedef unsigned char byte; \
               struct S { char c; int i; }; \
               int main(void){ byte b; b = 200; \
                 return b + sizeof(struct S); }"),
    ("pointers_address_of_and_deref",
        "int main(void){ int x; int *p; x = 5; p = &x; \
               *p = *p + 37; return x; }"),
    ("arrays_subscript_and_compound_assign",
        "int main(void){ int a[5]; int i; int s; s = 0; \
               for (i = 0; i < 5; i++) a[i] = i * i; \
               for (i = 0; i < 5; i++) s += a[i]; return s; }"),
    ("char_pointer_strlen",
        "int slen(char *s){ int n; n = 0; while (*s) { n++; s++; } return n; } \
               int main(void){ return slen(\"hello, world\"); }"),
    ("pointer_arithmetic_indexes_chars",
        "int main(void){ char *s; s = \"abcdef\"; return s[4]; }"),
    ("global_variable_state",
        "int g; int bump(void){ g = g + 1; return g; } \
               int main(void){ g = 40; bump(); bump(); return g; }"),
    ("sizeof_types",
        "int main(void) { return sizeof(int) + sizeof(char) + sizeof(int*); }"),
    ("integer_cast_truncates",
        "int main(void){ int x; x = 300; return (char)x; }"),
    ("ternary_and_prefix_postfix",
        "int main(void){ int a; a = 7; return a > 5 ? 100 : 200; }"),
    ("char_array_buffer_writes",
        "int main(void){ char b[4]; b[0] = 'O'; b[1] = 'K'; \
               b[2] = 33; b[3] = 0; return b[0] + b[1]; }"),
    ("unsigned_division_and_shift",
        "int main(void){ unsigned int x; x = 4294967295; return x / 2; }"),
    ("string_global_and_printf",
        "char *msg = \"global string\\n\"; \
               int main(void){ printf(\"global string\\n\"); return msg[0]; }"),
    ("preprocessor_object_and_function_macros",
        "#define N 7\n#define SQ(x) ((x)*(x))\n\
               int main(void){ return SQ(N); }"),
    ("preprocessor_conditional_compilation",
        "#define LEVEL 2\n\
               int main(void){\n\
               #if LEVEL > 1\n  return 10;\n#else\n  return 20;\n#endif\n}"),
    ("system_include_is_stubbed_and_printf_works",
        "#include <stdio.h>\n#include <stdlib.h>\n\
               int main(void){ printf(\"inc-ok\\n\"); return 0; }"),
    ("prototype_then_definition_links",
        "int add(int a, int b);\n\
               int main(void){ return add(19, 23); }\n\
               int add(int a, int b){ return a + b; }"),
    ("ifndef_include_guard_pattern",
        "#ifndef ONCE\n#define ONCE\n\
               int helper(void){ return 5; }\n#endif\n\
               int main(void){ return helper() * 8; }"),
    ("printf_writes_string_to_stdout",
        r#"int main(void){ printf("Hello, world!\n"); return 0; }"#),
    ("puts_appends_newline",
        r#"int main(void){ puts("hi"); return 0; }"#),
    ("printf_returns_byte_count",
        r#"int main(void){ return printf("abc"); }"#),
    ("adjacent_string_literals_concatenate",
        r#"int main(void){ printf("foo" "bar"); return 0; }"#),
    ("output_from_loop_and_callee",
        r#"
        int greet(void) { printf("hi\n"); return 0; }
        int main(void) {
            int i;
            for (i = 0; i < 3; i = i + 1) greet();
            printf("done\n");
            return 0;
        }"#),
    ("escape_sequences_in_output",
        r#"int main(void){ printf("a\tb\\c\"d"); return 0; }"#),
    ("nested_calls_as_arguments",
        "int add(int a, int b) { return a + b; } \
                int sq(int x) { return x * x; } \
                int main(void) { return add(sq(3), sq(add(2, 2))); }"),
];
