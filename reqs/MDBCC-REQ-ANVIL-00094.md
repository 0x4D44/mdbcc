# MDBCC-REQ-ANVIL-00094 — ABI torture matrix is hand-graded only — no differential arm against any reference

- **State:** Draft
- **Priority:** Could
- **Area:** Testing & oracles
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add an optional differential arm to `abi_torture` (reusing the existing harness) that, when cl/bcc32 are active, builds each ABI case with the reference and compares exit codes, falling back to the hand sentinel when the reference is absent so the suite stays green on a bare box.

## Rationale
The ABI matrix — home of historically fragile call-shape bugs (F-01/F-04/F-26) — is graded purely against author-asserted `expected_exit` sentinels, so an ABI shape that is wrong in *both* mdbcc and the author's mental model passes. It is a regression guard, not a correctness oracle.

- **Current:** Each ABI case's expected exit is asserted by the test author with no reference derivation.
- **Expected (BCC 4.52):** Where the ABI is shared-enough, the expected exit should be *derived* from a reference compiler (cl for Win64, bcc32/4.52 for i386) for the same source, not asserted.
- **Blocks:** ABI correctness confidence (S2/S7).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **TST-05** — severity low, type testing, effort M, status new.

- **Evidence:** `C:\language\mdbcc\tests\abi_torture.rs:73-249` carry `expected_exit: 42` hand-sentinels; `generated_win64_abi_torture_runs_hand_expected` (line 410) and the i386 variant (433) assert against the hand value with no cl/bcc32 cross-check; `quality_map.rs:82` notes "no MSVC/BCC differential arm yet." A differential harness exists (`tests/differential.rs` + `tests/support/bcc_oracle.rs`) but operates only over `tests/corpus/{portable,dialect}` and never sees the purpose-built ABI cases.
- **Proposed acceptance oracle (set at Gate 1):** With cl active, each Win64 ABI case's exit is compared to the cl-built reference, and a deliberately-wrong hand sentinel is caught by the differential.
