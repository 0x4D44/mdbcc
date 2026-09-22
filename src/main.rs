//! `bcc` — the mdbcc compiler driver (named after Borland's BCC.EXE).
//!
//! Capability so far: compile a single translation unit (functions returning
//! integer expressions) directly to a runnable Win64 PE `.exe`. No external
//! assembler or linker is used. `--dump-tokens` prints the token stream.
//!
//! S1b.5 (HLD §1.4): the `-c` flag stops after producing a COFF `.obj`
//! instead of an `.exe`. The compile pipeline forks at the codegen↔world
//! seam — `compile_to_object` produces an `mdbcc::coff::Object` which is
//! serialised via `Object::write()` and written to disk. Future S1c
//! (`mdlink`) will consume one or more of these `.obj` files to produce a
//! PE; in the meantime the resulting `.obj` is consumable by `lld-link` /
//! `link.exe` (the format-conformance gate in `tests/cli_dash_c.rs`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mdbcc::Lexer;
use mdbcc::codegen::target::TargetKind;
use mdbcc::compile::{
    compile_to_object_with_target_defines, compile_to_pe_with_rc_defines, is_cxx_source,
    preprocess_to_tokens,
};
use mdbcc::pp::{self, DefaultResolver, IncludeResolver, SearchPathResolver};
use mdbcc::rc;

/// Output kind. Selected by CLI: `-c` flips this from `Pe` to `Obj`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputKind {
    /// Today's path: compile + in-process link to a runnable Win64 PE `.exe`.
    Pe,
    /// HLD §1.4 `-c`: compile to a COFF `.obj` and exit. No link step.
    Obj,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("bcc");

    let mut dump_tokens = false;
    let mut preprocess_only = false;
    let mut output_kind = OutputKind::Pe;
    let mut target = TargetKind::Win64;
    let mut inputs: Vec<String> = Vec::new();
    let mut output: Option<String> = None;
    // S3: `-I <dir>` (repeatable) system-header search paths, in order.
    let mut include_dirs: Vec<PathBuf> = Vec::new();
    // `-D<name>[=<value>]` (repeatable) command-line object-macro definitions,
    // as `(name, value)`. A bare `-DNAME` defines NAME to `1` (the bcc/cpp
    // convention); `-DNAME=` defines it empty. Required to build real OWL apps
    // (`APPLICAT.H` #errors unless `WIN30`/`WIN31` is defined — the bcc32 IDE
    // build passes `-DWIN31`).
    let mut defines: Vec<(String, String)> = Vec::new();
    let mut it = args[1..].iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dump-tokens" => dump_tokens = true,
            // S3: `-E` preprocess-only. Lex + preprocess the TU, print the
            // resulting tokens to stdout, exit 0 on success / non-zero on a
            // preprocessor error. Stops before parse/codegen.
            "-E" => preprocess_only = true,
            "-c" => output_kind = OutputKind::Obj,
            // S2b.2: select the 32-bit i386 target. `-m32` emits a COFF
            // i386 object (link it with `mdlink -m32`); `-m64` is the
            // historical default. Direct-to-PE for `-m32` is deferred to
            // S2-future (the in-process CRT is x64 today) — use `-c`.
            "-m32" => target = TargetKind::Win32,
            "-m64" => target = TargetKind::Win64,
            "-o" => match it.next() {
                Some(o) => output = Some(o.clone()),
                None => {
                    eprintln!("{prog}: error: -o requires an argument");
                    return ExitCode::FAILURE;
                }
            },
            // S3: `-I <dir>` (separate) — collect a system-header search dir.
            "-I" => match it.next() {
                Some(d) => include_dirs.push(PathBuf::from(d)),
                None => {
                    eprintln!("{prog}: error: -I requires an argument");
                    return ExitCode::FAILURE;
                }
            },
            "-h" | "--help" => {
                print_usage(prog);
                return ExitCode::SUCCESS;
            }
            // S3: `-Idir` (glued, Borland-style) — the dir is the arg suffix.
            s if s.starts_with("-I") => include_dirs.push(PathBuf::from(&s[2..])),
            // `-D <name>[=<value>]` (separate) and `-D<name>[=<value>]` (glued).
            "-D" => match it.next() {
                Some(d) => defines.push(split_define(d)),
                None => {
                    eprintln!("{prog}: error: -D requires an argument");
                    return ExitCode::FAILURE;
                }
            },
            s if s.starts_with("-D") => defines.push(split_define(&s[2..])),
            s if s.starts_with('-') => {
                eprintln!("{prog}: error: unknown option '{s}'");
                return ExitCode::FAILURE;
            }
            s => inputs.push(s.to_string()),
        }
    }

    // S1c.10 (HLD §1.4, Q-Bcc ratified): bcc accepts ONE source file.
    // Multi-file builds belong to `mdlink` (compile each .cpp to .obj with
    // `bcc -c`, then link with `mdlink *.obj`). The message names the
    // workaround so users don't have to guess.
    if inputs.len() > 1 {
        eprintln!(
            "{prog}: error: bcc accepts a single source file ({} given).\n\
             For multi-file builds: compile each .cpp with `bcc -c`,\n\
             then link the resulting .obj files with `mdlink`.\n\
             (multi-file bcc deferred to S8 per HLD §10 Q-Bcc.)",
            inputs.len()
        );
        return ExitCode::FAILURE;
    }

    let Some(path) = inputs.into_iter().next() else {
        print_usage(prog);
        return ExitCode::FAILURE;
    };

    let src = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{prog}: error: cannot read '{path}': {e}");
            return ExitCode::FAILURE;
        }
    };

    if dump_tokens {
        return match Lexer::tokenize(&src) {
            Ok(tokens) => {
                for t in &tokens {
                    println!("{:>4}:{:<3} {:?}", t.line, t.col, t.kind);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{path}:{e}");
                ExitCode::FAILURE
            }
        };
    }

    // Resolve `#include "..."` relative to the input file's directory.
    let base_dir = Path::new(&path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    // S3: with `-I` dirs, search them (case-insensitively) for system headers
    // before stubbing; with NO `-I` keep the byte-for-byte legacy behaviour
    // (a bare `DefaultResolver`), so every existing test path is unaffected.
    let resolver: Box<dyn IncludeResolver> = if include_dirs.is_empty() {
        Box::new(DefaultResolver { base_dir })
    } else {
        Box::new(SearchPathResolver {
            dirs: include_dirs,
            fallback: DefaultResolver { base_dir },
        })
    };
    let resolver: &dyn IncludeResolver = resolver.as_ref();

    // S3: `-E` preprocess-only — run lex + preprocess, print tokens, exit.
    if preprocess_only {
        // Dialect from the source extension — a `.cpp`/`.cc`/`.cxx`/`.C`
        // source predefines `__cplusplus` so C++-guarded headers (OWL/BIDS
        // `#error Must use C++`) preprocess instead of tripping the guard.
        // Previously hardcoded `false`, so `-E` on a C++ TU wrongly fired the
        // guard (and never matched the compile path's expansion).
        return match preprocess_to_tokens(&src, &path, resolver, is_cxx_source(&path)) {
            Ok(tokens) => {
                for t in &tokens {
                    if t.kind == mdbcc::TokenKind::Eof {
                        continue;
                    }
                    if let Some(s) = pp::spelling(&t.kind) {
                        println!("{s}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{path}:{e}");
                ExitCode::FAILURE
            }
        };
    }

    // S2b.2: the in-process PE link path synthesises an x64 CRT only.
    // `-m32` therefore requires `-c` (emit an i386 .obj, then link it with
    // `mdlink -m32`). Fail loudly rather than emit an x64 PE under `-m32`.
    if target == TargetKind::Win32 && output_kind == OutputKind::Pe {
        eprintln!(
            "{prog}: error: -m32 requires -c for now (compile to an i386 \
             .obj, then link with `mdlink -m32`). Direct -m32 PE output is \
             deferred (the in-process CRT is x64-only)."
        );
        return ExitCode::FAILURE;
    }

    match output_kind {
        OutputKind::Obj => {
            // HLD §1.4: compile to COFF Object, serialise, write `.obj`,
            // exit. No `.rc` resource handling (resources are a per-image
            // construct synthesised by the linker, not per-TU).
            let obj = match compile_to_object_with_target_defines(
                &src, &path, resolver, target, &defines,
            ) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("{path}:{e}");
                    return ExitCode::FAILURE;
                }
            };
            let bytes = obj.write();
            let out = output.unwrap_or_else(|| default_obj_output(&path));
            if let Err(e) = std::fs::write(&out, &bytes) {
                eprintln!("{prog}: error: cannot write '{out}': {e}");
                return ExitCode::FAILURE;
            }
            println!("{prog}: wrote {out} ({} bytes)", bytes.len());
            ExitCode::SUCCESS
        }
        OutputKind::Pe => {
            // Phase G / G3: auto-detect a sibling `.rc` to the input source.
            // If `foo.c` is compiled and `foo.rc` exists in the same
            // directory, parse it and let the PE writer emit a `.rsrc`
            // section. No CLI flag — same single-driver UX as Borland's
            // `bcc32` (HLD §G3 / Open Question 3).
            let rc_path = Path::new(&path).with_extension("rc");
            // W5 (rc gap 2): `fs::read` + `parse_bytes`, not `read_to_string`
            // — a 1990s `.rc` is Latin-1 and may not be valid UTF-8.
            let rc_unit = match std::fs::read(&rc_path) {
                Ok(bytes) => match rc::parse_bytes(&bytes) {
                    Ok(unit) => Some(unit),
                    Err(e) => {
                        eprintln!("{}:{e}", rc_path.display());
                        return ExitCode::FAILURE;
                    }
                },
                Err(_) => None, // no sibling .rc; the PE has no `.rsrc` section
            };

            let exe = match compile_to_pe_with_rc_defines(
                &src,
                &path,
                resolver,
                rc_unit.as_ref(),
                &defines,
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("{path}:{e}");
                    return ExitCode::FAILURE;
                }
            };

            let out = output.unwrap_or_else(|| default_output(&path));
            if let Err(e) = std::fs::write(&out, &exe) {
                eprintln!("{prog}: error: cannot write '{out}': {e}");
                return ExitCode::FAILURE;
            }

            println!("{prog}: wrote {out} ({} bytes)", exe.len());
            ExitCode::SUCCESS
        }
    }
}

/// Replace the input extension with `.exe` (Borland-style default output).
fn default_output(input: &str) -> String {
    let stem = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("a");
    format!("{stem}.exe")
}

/// Replace the input extension with `.obj` (MSVC/Borland-style default for
/// `-c` mode). `foo.cpp` → `foo.obj`, `bar.c` → `bar.obj`.
fn default_obj_output(input: &str) -> String {
    let stem = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("a");
    format!("{stem}.obj")
}

/// Split a `-D` argument into `(name, value)`. `NAME=value` splits at the
/// first `=`; a bare `NAME` defines it to `"1"` (the bcc/cpp convention);
/// `NAME=` defines it to the empty string.
fn split_define(arg: &str) -> (String, String) {
    match arg.split_once('=') {
        Some((name, value)) => (name.to_string(), value.to_string()),
        None => (arg.to_string(), "1".to_string()),
    }
}

fn print_usage(prog: &str) {
    eprintln!(
        "usage: {prog} [--dump-tokens] [-E] [-c] [-m32|-m64] \
         [-D<name>[=<value>]]... [-I <dir>]... [-o <out>] <file.c|file.cpp>"
    );
}
