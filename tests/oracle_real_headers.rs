//! S3 — real Borland header COMPILE oracle (the bounded first step toward the
//! HELLOWIN.C S3 exit). Where `oracle_o15_header_acceptance.rs` measures
//! *preprocessor* acceptance of the 246 `\BC45\INCLUDE\*.h` headers, this suite
//! goes the whole way for a couple of small, widely-used real headers:
//! `#include` them, **PARSE** their declarations, generate i386 code, link a
//! PE32, run it on WOW64, and (when the BCC 4.52 oracle is present) assert the
//! exit code matches `bcc32`.
//!
//! The headers under test (`<string.h>`, `<stddef.h>`, `<stdlib.h>`) declare
//! their RTL functions with the Borland calling-convention macros (`_RTLENTRY`
//! → `__cdecl`) and `typedef` the standard types (`size_t`, `ptrdiff_t`,
//! `atexit_t`, …). mdbcc already provides intrinsic `strlen`/`strcpy`/… via
//! `gen_libc`, so the header's job here is purely to *parse* without error —
//! the builtin does the actual work, and a header *prototype* must NOT defeat
//! the intrinsic (it is not a definition).
//!
//! Self-skips loudly when the `\BC45\INCLUDE\` tree is absent (mirrors the
//! O15 / `oracle_bcc452` self-skip idiom), so the suite stays green on a
//! machine without the BC45 CD.

#![cfg(windows)]

mod support;

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use mdbcc::Lexer;
use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::parser::Parser;
use mdbcc::pp::{self, DefaultResolver, IncludeResolver, SearchPathResolver};

use support::bcc_oracle::{BccOracle, BuildOpts};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The real `\BC45\INCLUDE\` tree — the `-I` search root for both toolchains.
fn include_dir() -> PathBuf {
    repo_root().join("wrk_oracle\\bc452\\BC45\\INCLUDE")
}

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Compile `src` through mdbcc's i386 codegen with a real-header search path
/// (`<...>` resolves over `include_dir()`, case-insensitively) and link to a
/// PE32 image — the `mdbcc -c -m32 -I <INCLUDE>` + `mdlink -m32` driver path.
fn mdbcc_i386_pe_with_includes(src: &[u8], inc: &Path) -> Vec<u8> {
    let resolver = SearchPathResolver {
        dirs: vec![inc.to_path_buf()],
        fallback: DefaultResolver {
            base_dir: PathBuf::from("."),
        },
    };
    let obj = compile_to_object_with_target(src, "main.c", &resolver, TargetKind::Win32)
        .expect("mdbcc i386 compile (real headers)");
    link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32")
}

/// Run a PE image with a 5 s timeout; `Some(code)` on clean exit, `None` if the
/// spawn/write failed (WOW64 refused the image — a loud skip, not a hard fail,
/// mirroring `i386_run.rs::run_pe`).
fn run_pe(pe: &[u8], tag: &str) -> Option<i32> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "mdbcc_realhdr_{tag}_{:x}.exe",
        std::process::id() as u64 * 0x1000 + Instant::now().elapsed().as_nanos() as u64,
    ));
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
                            panic!("{tag}: i386 PE hung (>5s)");
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

/// The shared check: compile `src` against the real headers, run it, assert the
/// exit code, and — when the oracle is present — assert `bcc32` (which builds
/// the same source with its own `-I <INCLUDE>`) exits the same. Self-skips when
/// the INCLUDE tree is absent.
fn check_real_header(tag: &str, src: &str, expected: i32) {
    let inc = include_dir();
    if !inc.is_dir() {
        eprintln!(
            "[{tag}] SKIP: {} not present (the BC45 INCLUDE tree is not on this machine).",
            inc.display()
        );
        return;
    }

    let pe = mdbcc_i386_pe_with_includes(src.as_bytes(), &inc);
    let Some(mdbcc_exit) = run_pe(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected, "[{tag}] mdbcc i386 exit");

    if let Some(oracle) = BccOracle::discover() {
        // The oracle compiles with its own `-I <INCLUDE>` / `-L <LIB>`, so the
        // bcc32 reference reads the SAME real headers.
        let r = oracle.build(src, &BuildOpts::default());
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[{tag}] bcc32 build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(mdbcc_exit),
            "[{tag}] mdbcc i386 exit ({mdbcc_exit}) must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE ({tag}): BCC 4.52 oracle absent — skipped bcc32 diff");
    }
}

/// The headline S3 first-step acceptance: a program over the REAL `<string.h>`
/// and `<stddef.h>` headers compiles, links, runs, and matches bcc32.
/// `strlen("hi")` is 2 and `sizeof(size_t)` is 4 (Borland `typedef unsigned
/// size_t;` on Win32), so the exit code is 6. The header supplies the
/// `__cdecl`-decorated prototypes and the `size_t` typedef; mdbcc's `gen_libc`
/// intrinsic performs the `strcpy`/`strlen` (the prototype must not turn them
/// into unresolved `_strcpy`/`_strlen` externs).
#[test]
fn real_string_stddef_strlen_sizeof() {
    check_real_header(
        "rh_string_stddef",
        "#include <string.h>\n\
         #include <stddef.h>\n\
         int main(void){ char b[8]; strcpy(b,\"hi\"); \
         return (int)strlen(b) + (int)sizeof(size_t); }",
        6,
    );
}

/// Adds `<stdlib.h>` to the include set — it surfaces the grouped
/// function-pointer typedef with an inner calling convention
/// (`typedef void (__cdecl *atexit_t)(void);`) plus the anonymous-struct
/// `div_t`/`ldiv_t` typedefs. Same observable behaviour (exit 6) as the
/// string/stddef program; this test pins that the additional header still
/// parses + the program still matches bcc32.
#[test]
fn real_string_stddef_stdlib_parse_and_run() {
    check_real_header(
        "rh_string_stddef_stdlib",
        "#include <string.h>\n\
         #include <stddef.h>\n\
         #include <stdlib.h>\n\
         int main(void){ char b[8]; strcpy(b,\"hi\"); \
         return (int)strlen(b) + (int)sizeof(size_t); }",
        6,
    );
}

// ===========================================================================
// Parse-acceptance ratchet (the broader S3-endgame metric, the parsing analogue
// of O15's preprocessor-acceptance count). For each real `\BC45\INCLUDE\*.h`
// header, `#include` it as a one-line TU (with a trailing `int main(){...}` so
// a declaration-only TU is not spuriously rejected — a pure-prototype unit has
// zero AST items and the parser/codegen expects at least one definition),
// preprocess in **C mode** (the compile path's dialect), and parse it. ACCEPT =
// `Parser::parse_for` returns `Ok` with no panic. This is the actionable gap
// list for the HELLOWIN.C endgame: each REJECT is a declaration form the parser
// does not yet accept. C mode is what the compile path uses, so this measures
// what actually matters for compiling C programs against the real headers.
//
// `catch_unwind` quarantines any panic so one bad header can't abort the sweep.
// ===========================================================================

/// Ratchet floor: the C-mode parse-acceptance count. The first S3 tick fixed
/// the `T * __cdecl name(...)` declarator position, the grouped-fn-ptr inner
/// convention (`void (__cdecl *p)(void)`), and the `wchar_t` C-mode typedef →
/// 78 / 246. The second tick (this one) added the real-header declaration forms
/// that dominate the Win32 SDK and let `<windows.h>` itself PARSE:
///   * **bit-fields** — `T name : width ;` and the anonymous `T : width ;` /
///     `int : 0 ;` padding (WINNT.H `_LDT_ENTRY`, IO.H `ftime`); syntax accepted,
///     sub-byte packing deferred;
///   * the **`__import`/`__export`/memory-model** qualifier run before a `*` in
///     a grouped declarator — `int (__stdcall __import *FARPROC)()` (`WINAPI` ==
///     `__stdcall __import`);
///   * "**east const**" — a cv-qualifier between a typedef-name base and the `*`
///     (`MENUITEMINFOA const *LPCMENUITEMINFOA`);
///   * **function-TYPE typedefs** — `typedef RET NAME(params);`,
///     `typedef RET (NAME)(params);`, and `typedef void (__stdcall NAME)(params);`
///     (DRVCALLBACK / HPPROVIDERINIT / QUERYHANDLER);
///   * **anonymous struct/union members** — `union { ... } ;` (MAPI `DTPAGE`);
///     syntax accepted, member promotion deferred.
///
/// These brought the standalone count to 111 / 246.
///
/// NOTE on the ceiling: the bulk of the remaining ~135 rejects are NOT parser
/// gaps. The BC45 Win32-SDK headers deliberately do not re-`#include <windows.h>`
/// in their 32-bit (`__FLAT__`) branch — they assume the user included it first
/// — so parsed in ISOLATION their `UINT`/`HWND`/`FAR`/`WINAPI` references are
/// genuinely-undefined identifiers ("expected a type"). With `<windows.h>`
/// pre-included, ~81 more of them parse cleanly (verified). The known genuine,
/// windows.h-independent gaps left are: SIGNAL.H (the `void (*signal(args))(int)`
/// function-returning-function-pointer declarator — a single header, deferred),
/// COBJPS.H (C++ `= 0` pure-virtual COM, S4), and TNEF.H (`[MAPI_DIM]`, a
/// prerequisite macro).
///
/// NOTE: the `extern "C"` linkage-specification work does NOT move this floor —
/// in **C mode** (`__cplusplus` undefined) every header guards its
/// `extern "C" { ... }` wrapper behind `#ifdef __cplusplus`, so the construct is
/// preprocessed away and never reaches the parser. `extern "C"` parsing instead
/// lifts the **C++-mode** count (`FLOOR_PARSE_CXX` below).
///
/// S5: the quote-include resolution fix (a quoted `#include "dir\file.h"` of a
/// real `-I` header was being shadowed by an empty stub) lifted this 111 → 112.
const FLOOR_PARSE_C: usize = 112;

/// Ratchet floor: the **C++-mode** parse-acceptance count (the same sweep with
/// `__cplusplus` defined — the dialect bcc32 uses when compiling these headers
/// as C++). In C++ mode the `#ifdef __cplusplus extern "C" { #endif ... #endif`
/// wrappers expand to real `extern "C" { ... }` linkage-specifications, so this
/// metric is what the C++ §7.5 linkage-spec parsing actually unblocks: adding it
/// took the C++-mode count from 47 → 77 / 246 (every header whose *only* parse
/// blocker was the unparsed `extern "C" {`). The remaining C++-mode rejects are
/// dominated by `expected a type` (C++ class/template constructs not yet
/// modelled — e.g. `<...>` template-ids, `::`-qualified names), then
/// `expected a member name` and `expected ';'`. Raise as later ticks accept more
/// C++ forms; never let it regress. (S3.8's conv-before-name acceptance also
/// lifted this 77 → 79; S4.2's BC++ 4.52 dialect fixes — implicit-int, the
/// `bool`/`true`/`false`/`mutable` keyword demotion, and literal `#include
/// "..."` header-names — lifted it 79 → 80 by letting CLASSLIB/DEFS.H's closure
/// parse.) S4.2's full class-template support (capture + single/multiple
/// instantiation + type-parameter bases) plus the member/expression-parse work
/// (forward member refs, named & functional casts, exception-specs, friend,
/// nested classes + multi-`::` out-of-line members, enum-as-type, operator
/// names incl. new/delete, leading-`::` and operator-by-name calls) lifted it
/// 80 → 116 — 36 more real headers now parse, including the CSTRING.H string-
/// class closure.
///
/// S4.2c then took the `<owl/applicat.h>` closure deeper through the IOSTREAM
/// chain: user-defined CONVERSION operators (`ios::operator void*`), qualified-
/// id constants in expressions (`ios::in | ios::out` default args), cast-vs-
/// parenthesised-expr disambiguation for `(Tag::value)`, and `virtual`-before-
/// access in a base clause (`class istream : virtual public ios`) lifted it
/// 116 → 124 (IOSTREAM.H, OWL/except, checks.h, ... now parse).
///
/// S4.2d then cleared the base-pointer-adjustment vtable blocker AND added an
/// empty `__rtti` macro, so TYPEINFO.H (`class __rtti typeinfo`) parses: 124 → 125.
///
/// S5: the quote-include resolution fix (a quoted `#include "dir\file.h"` of a
/// real `-I` header was shadowed by an empty stub, dropping the included
/// declarations) lifted this 125 → 126.
const FLOOR_PARSE_CXX: usize = 126;

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

/// Lex → preprocess → parse `#include <header>` + a trivial `main`, catching
/// panics. `cxx` selects the preprocessor dialect: `false` = C mode (the
/// compile path's dialect, `__cplusplus` undefined), `true` = C++ mode (where
/// the `#ifdef __cplusplus extern "C" { #endif` wrappers become real
/// linkage-specifications). `true` return = the header's declarations parsed
/// cleanly.
fn header_parses(dir: &Path, header: &str, cxx: bool) -> bool {
    let resolver = SearchPathResolver {
        dirs: vec![dir.to_path_buf()],
        fallback: DefaultResolver {
            base_dir: dir.to_path_buf(),
        },
    };
    let tu = format!(
        "#include <{}>\nint main(void){{return 0;}}\n",
        header.to_ascii_lowercase()
    );
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let tokens = Lexer::tokenize(tu.as_bytes()).ok()?;
        let pt = pp::preprocess(tokens, header, &resolver as &dyn IncludeResolver, cxx).ok()?;
        Parser::parse_for(&pt, 4).ok().map(|_| ())
    }));
    matches!(result, Ok(Some(())))
}

/// Shared body for both parse-acceptance ratchets: sweep every header in the
/// chosen dialect and assert the PARSE-OK count holds the floor. Self-skips
/// (prints, returns) when the INCLUDE tree is absent.
fn run_parse_ratchet(cxx: bool, floor: usize, label: &str) {
    let dir = include_dir();
    if !dir.is_dir() {
        eprintln!(
            "[parse-ratchet] SKIP: {} not present (BC45 INCLUDE tree absent).",
            dir.display()
        );
        return;
    }

    let headers = list_headers(&dir);
    let total = headers.len();
    assert!(total > 0, "no .h headers found under {}", dir.display());

    let n = headers
        .iter()
        .filter(|h| header_parses(&dir, h, cxx))
        .count();
    println!("\n=== S3 parse-acceptance ({label}) ===");
    println!("TOTAL {total}  |  PARSE-OK {n}  REJECT {}", total - n);
    println!("PARSE-OK {n} / {total}  (floor = {floor})");

    assert!(
        n >= floor,
        "parse-acceptance regression ({label}): only {n} headers parse \
         (floor is {floor}). A parser change rejected a declaration form a \
         real header needs."
    );
}

/// C-mode parse-acceptance ratchet — the compile path's dialect (the metric
/// that gates compiling C programs against the real headers).
#[test]
fn o15_parse_acceptance_c_mode_ratchet() {
    run_parse_ratchet(false, FLOOR_PARSE_C, "C mode");
}

/// C++-mode parse-acceptance ratchet — `__cplusplus` defined, so the
/// `#ifdef __cplusplus extern "C" { #endif` wrappers expand to real C++ §7.5
/// linkage-specifications. This is the metric the `extern "C"` linkage-spec
/// parsing lifts (47 → 77 / 246).
#[test]
fn o15_parse_acceptance_cxx_mode_ratchet() {
    run_parse_ratchet(true, FLOOR_PARSE_CXX, "C++ mode");
}
