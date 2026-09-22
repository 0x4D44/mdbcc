# MDBCC-REQ-ANVIL-00103 — 82 scattered inline target branches; the `Target` trait is unused for dispatch

- **State:** Draft
- **Priority:** Should
- **Area:** Maintainability / tech-debt
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Route codegen's target-dependent decisions through the `Target` trait / a per-target ABI struct, and converge the `_i386`/Win64 forked functions onto a shared body parameterized by target where the logic is the same.

## Rationale
Every i386-vs-Win64 difference is an ad-hoc `if self.target == …` or a `_i386`-suffixed clone of the Win64 function, even though a `Target` trait already exists; the two targets then drift independently.

- **Current:** Target-specific behaviour is sprayed across 82 call sites and parallel `_i386` clones; the "EH split-target hazard" (Win64 EH fixed while i386 SEH3 lags) is a direct symptom — the i386 throw path is a separate function that never received the cleanup-pad work.
- **Expected (BCC 4.52):** A trait-based or table-based ABI seam (one impl per target) so a fix lands once for both targets, matching the intent of the present `Target` trait.
- **Blocks:** none (the forked-path drift raises the cost/risk of S7 64-bit parity work, but the project explicitly deferred this XL refactor; the underlying i386 gaps like 64/64 divide and SEH3 cleanup pads are separately parked and independently fixable).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-03** — severity medium, type tech-debt, effort XL, status sharpens-parked.

- **Evidence:** `src/codegen.rs` contains 82 inline target conditionals (80 `TargetKind::Win32`, 47 `TargetKind::Win64` mentions; e.g. lines 3508, 3691, 3788, 3803, 3842, 3882, 4004, 4041, 4202, 4513, 4878, 5081, 5544). `src/codegen/target.rs:93+` defines a `Target` trait (`ptr_bytes`/`coff_machine`/`rip_relative`/`seh_kind`) that codegen never dispatches through. Forked functions: `gen_throw_class` (6315) vs `gen_throw_class_i386` (6481), `gen_new_array` (16569) vs `gen_new_array_i386` (17000), plus `store_tmp_i386_i64`, `gen_intop_i386_i64`. The deferral is documented at `target.rs:9-34` (supervisor Decision-1c.2).
- **Proposed acceptance oracle (set at Gate 1):** Inline `TargetKind::` branches in codegen.rs roughly halve; the throw/new-array i386-vs-win64 pairs share a common body; baselines for both `-m32` and `-m64` stay green.
