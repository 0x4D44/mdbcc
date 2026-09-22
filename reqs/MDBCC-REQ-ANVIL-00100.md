# MDBCC-REQ-ANVIL-00100 — No automated perf-regression guard

- **State:** Draft
- **Priority:** Could
- **Area:** Performance
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add at least one non-ignored, machine-robust scalability test that fails if a hot path goes quadratic — preferably by counting an instrumented work metric (e.g. symbol-scan or header-lex count) rather than timing, so it is deterministic in CI.

## Rationale
`perf_harness` asserts only that compilation succeeds, never on timing, and both tiers are `#[ignore]` so they never run in `cargo test`; there is no ratio- or instrumented-count regression check, so a re-introduced O(n²) hot path would not be caught automatically.

- **Current:** The only protection against re-introducing a quadratic is a human re-running the harness `--release --ignored`; given codegen.rs is the documented scale hot-zone, regressions are likely to go unnoticed until a big build feels slow.
- **Expected (BCC 4.52):** A scalability guard need not assert wall-clock; it can assert algorithmic shape — compile at sizes N and 4N and bound time(4N)/time(N) below a super-linear-but-not-quadratic threshold, or count an instrumented operation (symbol rescans, header lexes) and assert it grows ~linearly, catching the O(n²) class that already bit twice.
- **Blocks:** Preventing regression of the G4 codegen fix and PERF-01–PERF-04 once they land.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PERF-06** — severity low, type testing, effort M, status new.

- **Evidence:** `tests/perf_harness.rs:20-22` ("assert only that compilation SUCCEEDS; they never assert on absolute timing"); both tiers `#[ignore]` at `tests/perf_harness.rs:135,155`; the G4 win (61s→1.25s) is recorded only in a journal, not gated by any test.
- **Proposed acceptance oracle (set at Gate 1):** A test, given a synthetic input at two sizes, asserts the chosen metric scales sub-quadratically; deliberately reintroducing a historical O(n²) scan (or PERF-01/PERF-02) makes it fail; it runs in default `cargo test` without `--release`/`--ignored` and uses no wall-clock assertion.
