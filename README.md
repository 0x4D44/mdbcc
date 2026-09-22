# mdbcc

A from-scratch reimplementation, in Rust, of the Borland C++ 4.52 toolchain for
Windows. It compiles C and C++ to native Win32 (i386) and Win64 (x64) PE
executables using its own preprocessor, parser, code generator, COFF writer,
linker, librarian and resource compiler. No external assembler, linker or C
runtime toolchain is involved.

The proof point is **RailC**, a ~12K-line Borland OWL Windows application. mdbcc
builds it from source, links it against the OWL/RTL/BIDS/iostream libraries it
compiled itself from the BC4.52 source tree, and runs it as a native 32-bit or
64-bit GUI app at pixel parity with the original.

## Tools

| Binary | Borland analogue | Role |
|---|---|---|
| `bcc` | `BCC.EXE` | Compiler driver. One translation unit to a `.obj` (`-c`) or straight to a runnable `.exe`. |
| `mdlink` | `TLINK32.EXE` | Linker. COFF `.obj`, `.lib` archives, `.def` files and `.res` resources to a PE32/PE32+ image. |
| `mdar` | `TLIB.EXE` | Librarian. Bundles `.obj` files into an MS-format `.lib` archive. |
| `mdrc` | `BRC32.EXE` | Resource compiler. `.rc` to `.res`, with `brc32` and `bc45` ordering profiles. |
| `mdbcc` | the IDE / make | Project runner. Builds an `mdbcc.toml` project end to end. |
| `build_bc45_libs` | none | Compiles the BC4.52 OWL, streams, RTL and BIDS sources into the runtime libraries the other tools link against. |

## Status

Done and gated by tests:

- C and C++ front end covering what BC4.52's headers, OWL and RailC need: classes, virtual and multiple inheritance, templates, overloading, exceptions, RTTI, Borland name mangling.
- Win32 (`-m32`) and Win64 (`-m64`) code generation with the matching calling conventions, structured exception handling and PE layout.
- RailC self-hosted on both targets, with GUI parity oracles against golden screenshots.
- Stock BC4.52 OWL sample applications built and run as products.
- Differential oracles against MSVC, Borland `bcc32` 5.5.1 and the BC4.52 toolchain itself, all of which self-skip when the reference tool is absent.

Known gaps are tracked in `BUGS.md`. The largest open ones are `__fastcall` and
`__pascal` silently lowering to cdecl, `#pragma pack` being ignored, and
member-function-pointer values that carry no `this` adjustment. The full audit
lives in `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md`.

## Building

Requires a stable Rust toolchain (edition 2024). The crate has no dependencies.

```powershell
cargo build --release --bins
```

To also produce the BC4.52 runtime libraries for both targets, run the
canonical build script:

```powershell
pwsh -NoProfile -File scripts/build-mdbcc.ps1
```

It writes `target/bc45-libs/{mdowl,mdstreams,mdcw32,mdbids}.lib` for Win32 and
the same set under `target/bc45-libs/win64/` for Win64. The two halves are also
available as `cargo bc45-libs` and `cargo bc45-libs-win64`.

The library step needs the Borland C++ 4.52 source tree. It is copyrighted and
not part of this repository. Point `MDBCC_BC45_ROOT` at your copy, or place it
at `wrk_oracle/bc452/BC45` or `C:\tmp\bc45`. Without it the step prints a skip
notice and exits 0, so a plain toolchain build never fails for its absence.

If you have no copy, `scripts/get-bc45.ps1` fetches one: it downloads the
WinWorld Borland C++ 4.52 archive (SHA-256 pinned), extracts the CD's `BC45`
tree into `wrk_oracle/bc452/BC45` with 7-Zip, then runs `build-mdbcc.ps1`.
Pass `-Archive <file.7z>` to use an archive you already have, `-Dest` to
install elsewhere, or `-SkipLibs` to stop after the install. Whether to run it
is your call: the compiler is still under copyright.

## Quick start

Compile and run a single file:

```powershell
.\target\release\bcc.exe hello.c -o hello.exe
.\hello.exe
```

Compile to an object and link explicitly:

```powershell
.\target\release\bcc.exe -c -m32 -I C:\bc45\INCLUDE main.cpp -o main.obj
.\target\release\mdlink.exe --subsystem gui --out app.exe main.obj target\bc45-libs\mdowl.lib
```

`bcc` accepts `-c`, `-E`, `-m32`, `-m64`, `-D<name>[=<value>]`, `-I <dir>`,
`-o <out>` and `--dump-tokens`. `mdlink` takes GNU-style options with MSVC
aliases (`--out`, `--subsystem`, `--entry`, `--image-base`, `--stack-reserve`).
Run any tool with `--help` for the full list.

Build a project from a manifest:

```toml
# mdbcc.toml
[package]
name = "app"
sources = ["src/main.cpp", "src/view.cpp"]
output = "bin/app.exe"
target = "win64"            # or "win32"
subsystem = "gui"           # or "console"
include_dirs = ["include", "C:/bc45/INCLUDE"]
overlay_dirs = []           # searched before include_dirs
defines = ["WIN31", "FEATURE=7"]
resources = ["app.rc"]
resource_profile = "bc45"   # or "brc32"
objects = []
libs = ["../mdbcc/target/bc45-libs/win64/mdowl.lib"]
```

```powershell
.\target\release\mdbcc.exe            # finds mdbcc.toml in cwd or a parent
.\target\release\mdbcc.exe --config path\to\mdbcc.toml
```

Intermediate objects and compiled resources go under `target/mdbcc/` next to
the manifest.

## Testing

```powershell
$null | cargo test
```

The suite is large. Integration tests live in `tests/` and each file covers one
area (`cpp_*`, `i386_*`, `win64_*`, `pe_*`, `rc_*`, `railc_*`, `owl_*`, and so
on). Oracle tests that need an external reference tool skip loudly when it is
missing, so a clean checkout passes without any of them.

| Environment variable | Enables |
|---|---|
| `MDBCC_BC45_ROOT` | BC4.52 source tree for `build_bc45_libs` and the RailC source-slice tests. |
| `MDBCC_LLVM_TEST_SUITE` | An `llvm-test-suite` checkout for the external corpus adapter. |
| `MDBCC_JOBS` | Parallel compile jobs in the project runner. |
| `MDBCC_TIME` | Per-phase timing output. |
| `MDBCC_BCC_ORACLE_DEBUG` | Keeps the BC4.52 oracle's work directories. |

The BC4.52 toolchain oracle looks for `wrk_oracle/bc452/BC45/BIN`. The MSVC and
`bcc32` 5.5.1 oracles are discovered on `PATH`. The `wrk_oracle/`, `wrk_corpus/`
and `wrk_tools/` directories are git-ignored and must stay so.

`scripts/coverage.ps1` runs `cargo llvm-cov` and appends a row to
`wrk_journals/coverage_history.tsv`.

## Repository layout

```
src/
  lexer.rs, pp.rs      tokeniser and preprocessor
  parser.rs, ast.rs    C/C++ front end
  codegen/             x64 and i386 code generation, ABI, C++ lowering, templates
  coff.rs              COFF object writer
  eh.rs                exception-handling tables
  link/                linker: archives, OMF, .def parsing, CRT glue, PE writer
  rc/                  resource compiler
  project.rs           mdbcc.toml runner
  compile.rs           the pipeline entry points
  bin/                 mdbcc, mdlink, mdar, mdrc, build_bc45_libs
  main.rs              bcc
tests/                 integration and oracle suites; tests/corpus holds fixtures
scripts/               build, coverage and closure scripts
wrk_owl_win64/         Win64 OWL overlay: mdbcc's own headers, plus unified diffs
                       in patches/ applied to your BC4.52 tree at build time
wrk_rtlshim/           C shims for RTL pieces the BC4.52 sources cannot provide
wrk_docs/              design docs, goals, gap analyses
wrk_journals/          engineering log and coverage history
notes/                 older handovers and design notes
reqs/                  requirements ledger
BUGS.md                defect ledger
```

## Contributing notes

Agent and contributor instructions are in `CLAUDE.md`. Non-obvious lessons are
in `lessons_learnt.md`; out-of-scope observations queue in `scratchpad.md`.

Borland's headers, runtime sources and the RailC application are not included.
You need your own licensed copies to reproduce the self-host results.

## Licence

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or
the MIT licence (`LICENSE-MIT`), at your option. Unless you state otherwise,
any contribution you intentionally submit for inclusion in this work, as
defined in the Apache-2.0 licence, is dual licensed as above without any
additional terms or conditions.

The Borland C++ 4.52 sources, headers and sample programs that the runtime
libraries and some tests are built from are not covered by this licence and
are not distributed here.
