# MDBCC-REQ-ANVIL-00095 — Header tokenize-once cache and `#pragma once` fast-skip

- **State:** Draft
- **Priority:** Should
- **Area:** Performance
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add a per-process header tokenize-once cache memoising resolved-path → `Vec<Token>` so a repeated `#include` reuses the cached stream, and short-circuit a guarded re-include (guard macro already defined, or `#pragma once` seen) without re-reading or re-lexing; emitted tokens for any TU must be byte-identical to today.

## Rationale
Every `#include` re-reads and re-lexes the header from disk; there is no tokenize-once cache and no `#pragma once` (or guard-macro) short-circuit, so a header pulled into N translation units is read and lexed N times.

- **Current:** Include guards prevent duplicate token *emission* but not the read + lex + conditional-skip work; with OWL/RTL headers pulled into dozens of TUs, the same multi-KLOC headers are re-tokenized on every inclusion.
- **Expected (BCC 4.52):** A from-scratch reimplementation targeting whole-OWL-tree rebuilds should not re-lex an identical, content-addressable header repeatedly; a path-keyed tokenize-once cache (or a guard-macro / `#pragma once` fast-skip that avoids re-reading when the guard macro is already defined) removes the dominant header cost the harness isolates.
- **Blocks:** G3/G4 build-perf scaling once codegen no longer dominates; multi-TU OWL/RTL/BIDS rebuild throughput (missions S5–S7).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PERF-01** — severity medium, type perf, effort M, status sharpens-parked.

- **Evidence:** `src/pp.rs:1226` (`resolve` does a fresh `std::fs::read` per include — `src/pp.rs:649,733,749`); `src/pp.rs:1235` (`Lexer::tokenize(&bytes)`) then `src/pp.rs:1241` (`self.run(toks)` re-processes the whole file); `src/pp.rs:1071` handles only `#pragma startup`, ignoring `#pragma once` (test `src/pp.rs:2542`); `tests/perf_harness.rs:14-18`.
- **Proposed acceptance oracle (set at Gate 1):** `perf_harness` tier-2 (`MDBCC_BENCH_INCLUDES=20`) median scales sub-linearly with include count; a new test asserts the same header is lexed once across multiple includes (e.g. a recording resolver shows resolve/lex counts drop); all existing pp/compile tests stay green with unchanged emitted tokens.
