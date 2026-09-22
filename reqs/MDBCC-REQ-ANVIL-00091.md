# MDBCC-REQ-ANVIL-00091 — The "fuzzer" is one fixed seed with a hardcoded hand-oracle — no generative or property coverage

- **State:** Draft
- **Priority:** Should
- **Area:** Testing & oracles
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Wire a real generator (a constrained in-dialect generator, or a Csmith/YARPGen subset gated on availability) against the existing differential references, or stand up a separate property-based no-panic/determinism oracle over a randomized input space.

## Rationale
There is no actual fuzzing: a single deterministic seed, one templated source shape, and a string-match oracle accepting exactly two shapes. It proves the reduction *plumbing* works on one canned case but gives zero ongoing coverage of unanticipated inputs.

- **Current:** One deterministic template plus a two-string hand-oracle. The file already self-labels (docstring `:1-6`, `quality_map.rs:73`) as a process proof/pilot, so it is not misrepresenting itself — the missing piece is the *capability*.
- **Expected (BCC 4.52):** A fuzz/property layer should generate varied in-dialect inputs and check them against a real reference (cl/bcc32/4.52) or a property oracle (compile-determinism, no-panic, round-trip), surfacing new divergences over time.
- **Blocks:** R5 broad-input confidence; unknown-unknown miscompiles.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **TST-02** — severity medium, type testing, effort L, status new.

- **Evidence:** `C:\language\mdbcc\tests\fuzz_reduction_path.rs:14` `const FUZZ_SEED` is one literal; `generate_case` (lines 48-71) emits one templated shape; `c89_exit_zero_oracle` (84-97) and `c89_smoke_shape_is_reference_valid` (99-102) hardcode the only accepted shapes by compacted-string match; the live red path (line 206) is `#[ignore]`; `quality_map.rs:73` states "process proof only; Csmith/YARPGen and external differential references are not wired yet." No proptest/quickcheck/cargo-fuzz exists; the gap is tracked at `quality_map.rs:298`.
- **Proposed acceptance oracle (set at Gate 1):** A multi-seed run (≥100 seeds) compiles varied generated TUs and asserts each either matches a reference or is excluded at a documented boundary; an injected known miscompile is caught by at least one seed.
