# MDBCC-REQ-ANVIL-00106 — Test harness helpers duplicated across files despite a shared support module

- **State:** Draft
- **Priority:** Should
- **Area:** Maintainability / tech-debt
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Consolidate the duplicated helpers (`run_with_timeout`, `build`, `discover_lld_link`, `run_pe_capture`) into `tests/support/` and have the ~55 non-support test files use them, deleting the local copies.

## Rationale
The same compile/link/run/timeout plumbing is copy-pasted with subtle signature drift across dozens of integration tests, even though `tests/support/` already provides reusable equivalents.

- **Current:** A change to timeout semantics, lld discovery, or capture handling must be made in many places or silently diverges; timeout discipline (CLAUDE.md mandates bounded test commands) is inconsistent.
- **Expected (BCC 4.52):** Internal maintainability requirement: integration tests share one harness so behaviour and timeout discipline are uniform.
- **Blocks:** none (reduces flake surface and gives uniform timing as S6/S7 add more OWL e2e gates).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-06** — severity medium, type testing, effort M, status new.

- **Evidence:** `tests/support/mod.rs` provides `run_with_timeout` (line 237), `RunOutcome`, `compare`, `mdbcc_compile`, `mdbcc_run`; yet only 23 of 78 test files reference it. `fn run_with_timeout` is re-defined locally in 7 files (`cli_dash_c.rs:54`, `cli_mdlink.rs`, `coff_i386_format.rs`, `coff_object_format.rs`, `o1_obj_byte_identity_cli.rs`, `oracle_s4_classlib.rs`, `project_config.rs`); `cli_dash_c.rs:54`'s copy has a divergent signature `(cmd, timeout) -> (Option<i32>, Vec<u8>, Vec<u8>)` vs support's `(cmd, timeout, cap) -> RunOutcome`. `fn build(` is defined 13× (differing only in temp-file prefix), `discover_lld_link` 3×, `run_pe_capture` 3×, `mdlink_exe` 2×.
- **Proposed acceptance oracle (set at Gate 1):** No test file outside `tests/support` defines `run_with_timeout`/`discover_lld_link`; the suite still passes; one definition of each helper remains.
