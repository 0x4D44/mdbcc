# MDBCC-REQ-ANVIL-00053 — Preprocessor lacks `#if`/`#elif`/`defined()`

- **State:** Draft
- **Priority:** Must
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Extend `src/rc/pp.rs` to support `#if`, `#elif`, and `defined(NAME)`/`defined NAME` with a constant-expression evaluator over the macro table (at minimum integer literals, `defined()`, `&& || !`, and comparison/bitwise ops), so a body guarded by `#if defined(RC_INVOKED)` is taken when `RC_INVOKED` is defined.

## Rationale
The RC preprocessor handles only `define`/`include`/`ifdef`/`ifndef`/`else`/`endif`/`undef`; `#if`, `#elif`, and the `defined()` operator are fatal errors, so every OWL resource header guarded by `#if defined(RC_INVOKED)` aborts compilation.

- **Current:** `#if` / `#elif` / `defined(NAME)` produce a fatal `unknown directive #if` RcError, aborting any `.rc` that includes an OWL resource header.
- **Expected (BCC 4.52):** BRC32 is a full C preprocessor: it evaluates `#if`/`#elif`/`#else`/`#endif` with constant-expression and `defined()` operators, exposing the guarded resource definitions in the OWL headers.
- **Blocks:** S6 OWL sample apps (any sample whose `.rc` pulls `owl\*.rc`).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-01** — severity high, type missing-feature, effort L, status new.

- **Evidence:** `src/rc/pp.rs:46-107` (directive match), `src/rc/pp.rs:104-106` (catch-all `unknown directive #{other}`); oracle `wrk_oracle/bc45/BC45/INCLUDE/owl/inputdia.rc:11`, `owl/slider.rc:11`; 92 INCLUDE files contain `RC_INVOKED`, 42 OWL example files use `#if`.
- **Proposed acceptance oracle (set at Gate 1):** `rc::compile_file` on a `.rc` that does `#include <owl/inputdia.rc>` compiles the `IDD_INPUTDIALOG` dialog rather than erroring; a unit test feeding `#if defined(RC_INVOKED)` … `STRINGTABLE` … `#endif` yields the string when defined and an empty unit when not.
