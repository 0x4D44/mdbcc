# MDBCC-REQ-ANVIL-00092 — Coverage measurement is a reporting script that gates nothing

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
Add a tracked line/region coverage floor for the mdbcc library crate that the coverage script asserts, and surface the per-module low-coverage list (notably the 285 `CodegenError` sites and 66 TODO regions) so feature-without-run-test gaps become a backlog signal rather than silent.

## Rationale
Coverage is a manual, ungated wrapper. Nothing fails when a new codegen path ships with no executing test, so the "codegen exists but no run-test" class of gap is invisible.

- **Current:** J-17 closure is manual reporting; the history file is written but never read back to gate.
- **Expected (BCC 4.52):** Coverage should be a tracked, periodically-checked number with a non-regression floor on the core crate, so newly-added codegen without a run-test is detectable.
- **Blocks:** Detection of feature-without-run-test gaps across all stones.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **TST-03** — severity medium, type testing, effort M, status new.

- **Evidence:** `C:\language\mdbcc\scripts\coverage.ps1:1-5` and `scripts/coverage.sh` wrap `cargo llvm-cov --workspace --release --summary-only`, appending one row to `wrk_journals/coverage_history.tsv` and exiting 0 by documented policy; `.cargo/config.toml` holds only `bc45-libs` aliases with no coverage integration; no test asserts a coverage floor, no CI, no `cargo cov` alias. Not mentioned in BUGS.md/scratchpad — untracked.
- **Proposed acceptance oracle (set at Gate 1):** `scripts/coverage.ps1` (or a `cargo cov` alias) exits non-zero when crate coverage drops below a pinned floor; the report names the lowest-covered codegen modules.
