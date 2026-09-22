//! O12 — corpus differential harness for the i386 (Win32) backend.
//!
//! For every fixture in `tests/corpus/portable/*.c` this test compiles, links
//! and runs the program through mdbcc's i386 backend, then compares its exit
//! code and stdout against the bcc32 + tlink32 reference (the BCC 4.52 oracle).
//!
//! It is deliberately a *ratchet*, not an all-pass gate: most fixtures exercise
//! constructs the i386 codegen does not lower yet (those `panic!` inside the
//! encoder and are classified COMPILE-GAP). The test asserts only that the
//! number of MATCH fixtures never drops below `FLOOR`, and prints a per-fixture
//! status table so the actionable S2 gap list is always visible.
//!
//! Per-fixture classification:
//!   - MATCH       — mdbcc built+ran it and its exit+stdout match bcc32.
//!   - MISMATCH    — mdbcc built+ran it but exit or stdout diverge from bcc32.
//!   - COMPILE-GAP — mdbcc's compile or link panicked / errored (unimplemented).
//!   - RUN-SKIP    — the mdbcc PE could not be spawned (environment issue).
//!   - REF-GAP     — bcc32 itself failed to build the fixture (reference fault).
//!
//! This file is a standalone integration test: it copies the minimal runner +
//! EOL-normalisation helpers from `tests/i386_run.rs` because integration test
//! binaries do not share private items.

mod support;

use std::io::Read as _;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;

use support::bcc_oracle::{BccOracle, BuildOpts};

/// Ratchet floor: the number of MATCH fixtures observed at authoring time
/// (arith, bigdata, control, manyargs, printf_width, recursion, unsigned),
/// plus pointers + structs after the S2 pointer-store fix (`store_at_rcx`
/// no longer emits a REX.W store for a 4-byte Win32 pointer/reference),
/// plus the 5 padded-printf fixtures (printf_length, printf_precision,
/// printf_width2, printf_zero, printf_zero2) once the padded-spec routines
/// (`fmt_int_spec`/`fmt_str_spec`/`fmt_char_spec`) grew Win32 branches,
/// plus bigcode + strings once plain `%s` (`fmt_str`) and the libc string
/// builtins (`gen_libc`: strlen/strcmp/strcpy/strcat/memcpy/memset/atoi)
/// grew Win32 branches,
/// plus funcptr once the indirect-call path (`emit_indirect_call_cdecl`)
/// grew a Win32 cdecl branch and the encoder gained a `call r32` row,
/// plus virtual once C++ virtual dispatch landed on i386: the `.rdata`
/// vtable layout grew Win32 4-byte slots + Addr32 relocs
/// (`plan_rdata_vtables`), `emit_virtual_call`/`SetVptr` grew cdecl Win32
/// branches (push `this`+args, `mov eax,[eax]` vptr, `slot*4` stride,
/// `call eax`), `marshal_args_cdecl` learned to push a leading `this`, and
/// `gen_new`/`gen_delete` grew __stdcall HeapAlloc/HeapFree branches,
/// plus printf_float once `%f`/`%.Nf` floating-point printf landed on i386:
/// FP literals load absolutely (`movsd xmm,[abs flit]`, a new X86Only
/// encoder row + `RipRef::Data`→Addr32 reloc) and `float_token` grew a
/// Win32 branch that keeps the value in SSE2 (xmm0-4) and pulls digits one
/// at a time (no 64-bit GPR), with edi/esi/ebx scratch (was r9/r11/r8);
/// `fmt_float_spec` zero-fill matches bcc32's sign-outside-width quirk,
/// plus exceptions once i386 fs:[0] SEH landed (S2e): a try-bearing function
/// installs an EXCEPTION_REGISTRATION on the `fs:[0]` chain in its prologue
/// (the 16-byte record reserved below the locals so it never aliases a
/// slot), `throw <int>` lowers to a __stdcall `RaiseException`, and the
/// module-wide `.mdbcc_seh3_handler` unwinds (`RtlUnwind`) to the catch pad.
/// Raise this as i386 coverage grows; it must never regress.
const FLOOR: usize = 20;

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Fold `\r\n` → `\n`. mdbcc emits bytes verbatim via `WriteFile`; bcc32's CRT
/// translates `\n` → `\r\n` in text mode on a pipe. Folding CRLF on both sides
/// compares the logical output, not the OS line discipline.
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
        "mdbcc_o12_{tag}_{:x}.exe",
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
/// Returns `Err` on a compile or link failure; panics propagate to the caller's
/// `catch_unwind` (the encoder `panic!`s on unimplemented constructs).
fn mdbcc_i386_pe(src: &[u8], file_name: &str, base_dir: &Path) -> Result<Vec<u8>, String> {
    let resolver = DefaultResolver {
        base_dir: base_dir.to_path_buf(),
    };
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
    // Same prefix, differing length.
    format!(
        "stdout length: mdbcc={} bytes, bcc={} bytes",
        mdbcc_out.len(),
        bcc_out.len()
    )
}

#[test]
fn o12_x86_corpus_differential() {
    let Some(oracle) = BccOracle::discover() else {
        eprintln!("SKIP: bcc32 oracle absent");
        return;
    };

    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/portable");
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "c"))
        .collect();
    fixtures.sort();

    // Suppress the encoder's noisy panic backtrace for the duration: the
    // catch_unwind below converts a panic into COMPILE-GAP, so the backtrace
    // is pure noise that would bury the status table. Restore afterwards.
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut results: Vec<(String, Status, String)> = Vec::new();

    for path in &fixtures {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let file_name = path.to_string_lossy().to_string();
        let Ok(src_bytes) = std::fs::read(path) else {
            results.push((name, Status::CompileGap, "could not read fixture".into()));
            continue;
        };

        // (a) compile + link via mdbcc, catching the encoder's panics.
        let built = panic::catch_unwind(AssertUnwindSafe(|| {
            mdbcc_i386_pe(&src_bytes, &file_name, &corpus_dir)
        }));
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

        // (c) build the same source with bcc32 (reference). A fixture whose
        // first line carries the `// oracle: lang cpp` directive is C++ (e.g.
        // virtual.c exercises classes / virtual dispatch / new+delete) — hand
        // bcc32 a `.cpp` so it parses C++, not C (otherwise it rejects the
        // class syntax and the fixture would show REF-GAP). mdbcc itself parses
        // the C++ subset regardless of extension, so only the oracle side keys
        // off the directive.
        let src_str = String::from_utf8_lossy(&src_bytes).into_owned();
        let lang = if src_str.lines().next().is_some_and(|l| {
            let l = l.trim();
            l.starts_with("//") && l.contains("oracle:") && l.contains("lang cpp")
        }) {
            support::bcc_oracle::Lang::Cpp
        } else {
            support::bcc_oracle::Lang::C
        };
        let r = oracle.build(
            &src_str,
            &BuildOpts {
                lang,
                ..BuildOpts::default()
            },
        );
        let Some(bcc_exe) = r.exe else {
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

    eprintln!("\n=== O12 i386 corpus differential ===");
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
        "\nMATCH {n_match} / {compiled_and_run} compiled-and-run ; \
         MISMATCH {n_mismatch} ; COMPILE-GAP {n_compile_gap} ; \
         RUN-SKIP {n_run_skip} ; REF-GAP {n_ref_gap}  (of {} fixtures)",
        results.len()
    );

    // ---- ratchet ------------------------------------------------------------
    // Green now; a floor for future work. Raise FLOOR as i386 coverage grows;
    // it must never regress. We deliberately do NOT assert all-pass — most
    // fixtures are known gaps.
    assert!(
        n_match >= FLOOR,
        "i386 corpus MATCH count regressed: {n_match} < floor {FLOOR}"
    );
}
