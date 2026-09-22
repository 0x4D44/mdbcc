# mdbcc — agent instructions

<!-- Hard cap 15 KB. Basic info, build/test/gate commands, version policy, signposts,
and the few unguarded hard rules. Durable facts go to lessons_learnt.md or a
design doc, never here (fleet `repo-adoption` skill, prose-file shape rule). -->

## What this is

A from-scratch Rust reimplementation of the Borland C++ 4.52 toolchain: `bcc`
(compiler), `mdlink` (linker), `mdar` (librarian), `mdrc` (resource compiler),
`mdbcc` (project runner) and `build_bc45_libs` (runtime-library builder). It
targets Win32 and Win64 PE and is proven by self-building the RailC OWL app.
`README.md` has the user-facing overview, CLI surface and `mdbcc.toml` schema.

Single crate, std only, edition 2024, no dependencies. Do not add one without
asking.

## Build

```powershell
cargo build --release --bins                    # the toolchain
pwsh -NoProfile -File scripts/build-mdbcc.ps1   # toolchain + BC4.52 runtime libs, both targets
```

The library step needs the copyrighted BC4.52 source tree (`MDBCC_BC45_ROOT`,
`wrk_oracle/bc452/BC45` or `C:\tmp\bc45`) and skips loudly without it.

## Test

Always close stdin: `$null | cargo test …`. Unit tests are in `src/`
(`cargo test --lib`); integration tests are one file per area in `tests/`.
Oracle suites self-skip when their reference tool is absent. A skip is a
correct result. Never make one pass by vendoring the missing tool or corpus.

Focused checks by area. Run these for the paths you touched, not the full suite:

| Area | `cargo test --test …` |
|---|---|
| lexer / preprocessor | `end_to_end error_locations oracle_o15_header_acceptance` |
| C++ front end | `cpp_* virtual cxx_mode borland_mangling` |
| x64 codegen / ABI | `i64_ops abi_torture win64_* calling floats` |
| i386 codegen / ABI | `i386_* win32_* encoder_table` |
| COFF / PE / linker | `coff_* pe_* two_file_link archive_link cli_mdlink oracle_o13_coff_parity oracle_o14_omf_link` |
| resource compiler | `rc_* cli_mdrc` |
| project runner | `project_config cargo_manifest_bins` |
| RailC / OWL product | `railc_* owl_* gui` (needs the BC4.52 tree and Win64 libs) |
| determinism | `o1_byte_identity determinism_stripe structural_invariants` |

Wildcards are illustrative; expand them from `ls tests`. Coverage:
`scripts/coverage.ps1` (appends to `wrk_journals/coverage_history.tsv`).

## Gate and version policy

Worktree-first; every task lands by `deltic integrate` from a task worktree.
Shipped code takes exactly one patch bump of `Cargo.toml` (and `Cargo.lock`
lockstep) at integration, never on the task branch. Test-only, docs and ledger
changes do not bump.

## Hard rules with no guard

- Never commit anything under `wrk_oracle/`, `wrk_corpus/`, `wrk_tools/` or a
  BC4.52 or RailC source file. They are third-party and copyrighted; the
  gitignore is the only fence.
- Never commit `.obj`/`.exe` probe output or anything under `wrk_probe/`.
- A change that alters RailC's emitted bytes must be deliberate: run the
  `railc_*` and `o1_byte_identity` suites and say in the commit what moved.
- External C corpora contain non-UTF-8 bytes. Preserve bytes or exclude the
  fixture at the corpus boundary; never transcode.
- The bug ledger is the flat `BUGS.md`, by this repo's choice. Do not create a
  `bugs/` directory or a `REQS.md`; `reqs/README.md` explains why.

## Signposts

- `README.md` — overview, tools, quick start, manifest schema, layout.
- `BUGS.md` — defect ledger (open / parked / fixed, with severities).
- `reqs/README.md` — requirements ledger schema and flow policy.
- `lessons_learnt.md` — index-v1 nuggets, newest first; prepend, never drop.
- `scratchpad.md` — dated `- [ ]` out-of-scope queue.
- `wrk_docs/` — HLDs, goals, dailies, the 2026-06-21 gap analysis.
- `wrk_journals/` — engineering log, coverage history, review notes.
- `notes/` — older handovers and design notes (pre-`wrk_docs`).
- `wrk_owl_win64/`, `wrk_rtlshim/` — shipped overlay sources for the Win64 OWL
  build and the RTL C shims; changes there ship. The Win64 OWL overlay is
  `patches/*.patch` — mdbcc's diffs only, never the Borland originals — applied
  to the user's own BC4.52 tree at build time by `src/overlay.rs`.
- No `ARCHITECTURE-GUIDE.md` yet. The module map is in `README.md` and
  `src/lib.rs`; create the guide on first need rather than growing this file.
