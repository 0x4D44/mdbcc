# MDBCC-REQ-ANVIL-00093 — Parked codegen gaps have no behaviour-encoding (clean-error or layout) oracle

- **State:** Draft
- **Priority:** Should
- **Area:** Testing & oracles
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add contract tests: (1) assert the clean `CodegenError` for i386 long-long `/`,`%` and the parked new-corner-forms; (2) add a bit-field `sizeof`+`offsetof` differential against the 4.52 oracle that records current divergences as an explicit tracked floor. Defer the long-double *value* differential until 80-bit storage (B-21) lands — there is nothing to differential against while it is folded to `double`.

## Rationale
Parked gaps (i386 long-long `/`,`%`; bit-field layout; long double) are documented but their *current contract* is unencoded, so a regression from a clean `CodegenError` to a silent wrong answer would not be caught, and there is no layout oracle to validate eventual support against 4.52.

- **Current:** The parked gaps are documented in prose only; nothing asserts the clean-error contract, and no layout differential records the known divergence.
- **Expected (BCC 4.52):** A clean-error gap needs a test asserting the clean error (so it cannot silently become a miscompile); a layout gap needs a recorded `sizeof`/`offsetof` differential against 4.52 (or 5.5.1) marking the known divergence to close.
- **Blocks:** Future long-double/bit-field work; guards the parked clean-error contracts against silent regression.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **TST-04** — severity medium, type testing, effort M, status sharpens-parked.

- **Evidence:** No long-double run/oracle test (only `i386_run.rs:2899 _control87`, unrelated); no bit-field differential test (only `external_corpus_adapter.rs:35-37` manifest entries, `#[ignore]`); `BUGS.md:60-65` parks long-double→double folding and inexact bit-field layout; `BUGS.md:34-36` parks i386 long long `/`,`%` as a clean `CodegenError`; error sites at `codegen.rs:11405/11744`, `parser.rs:7703`, `codegen.rs:15682`.
- **Proposed acceptance oracle (set at Gate 1):** A test fails if i386 `long long a/b` ever compiles to a non-erroring (wrong) result; a bit-field layout differential prints mdbcc-vs-reference offsets and is wired so closing the gap flips it to MATCH.
