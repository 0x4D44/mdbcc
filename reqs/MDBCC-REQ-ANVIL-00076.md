# MDBCC-REQ-ANVIL-00076 — Parser is fail-fast: one error per compile, no recovery/resync

- **State:** Draft
- **Priority:** Could
- **Area:** Diagnostics
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
The parser should resynchronize at declaration/statement boundaries after an error, accumulate multiple `ParseError`s, and the driver should report them all (up to a sensible cap) before failing.

## Rationale
The parser propagates the first `ParseError` and stops — no resynchronization at declaration/statement boundaries, no error accumulation, no error-limit cap; the driver and codegen are likewise fail-fast.

- **Current:** A source file with three independent syntax errors reports only the first; the user must fix-and-recompile iteratively, re-paying full preprocess+parse each cycle.
- **Expected (BCC 4.52):** bcc32 recovers at statement/declaration boundaries and reports many errors in one pass (up to its error limit), so a user sees most problems at once.
- **Blocks:** Developer ergonomics when porting/fixing real C/C++ TUs; not on the critical path for already-clean BC4.52 source.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DIAG-02** — severity low, type diagnostics, effort XL, status new.

- **Evidence:** `src/parser.rs:469-471` top loop (`while !p.at_eof() { p.external_declaration(&mut items)?; }`); single-struct `ParseError` at `src/parser.rs:14-19` (not a `Vec`); single `CompileError` threaded through `src/compile.rs:13-33`; no `errors.push`/`synchronize`/`resync` anywhere.
- **Proposed acceptance oracle (set at Gate 1):** A test feeds a TU with N independent top-level syntax errors and asserts N (capped) distinct diagnostics with correct line numbers are reported in one compile invocation.
