# MDBCC-REQ-ANVIL-00078 — Overload-resolution failure gives no candidate list or argument types

- **State:** Draft
- **Priority:** Could
- **Area:** Diagnostics
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Overload-failure diagnostics must include the actual argument types of the call and the signatures of the candidates considered (or at least the closest viable ones); thread the already-computed argtys and candidate signatures into the error string.

## Rationale
On an unresolved overloaded call/ctor the diagnostic carries only the qualified callee name — no actual argument types and no candidate signatures — even though `resolve_overload` computes the argument types and then discards them. This is exactly the message a developer hits on the documented OWL GROUPBOX/EDIT failures.

- **Current:** The user sees only `no matching overload for call to 'TGroupBox::TGroupBox'` — no argument types, no list of rejected candidates.
- **Expected (BCC 4.52):** bcc32 emits `Could not find a match for 'TGroupBox::TGroupBox(<actual arg types>)'` and, on ambiguity, lists the competing candidates, letting the user see which conversion failed.
- **Blocks:** Root-causing the GROUPBOX/EDIT (and similar) OWL sample overload failures toward S6.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DIAG-04** — severity low, type diagnostics, effort M, status new.

- **Evidence:** `src/codegen.rs:8116` (`no matching overload for call to '{cand}'`); `src/codegen.rs:14512-14513` (`ambiguous call to overloaded '{name}'` / `no matching overload for call to '{name}'`); `resolve_overload` at `src/codegen.rs:14250` returns `Ok(None)` with no detail; argtys computed at `src/codegen.rs:14261` then dropped; scratchpad records `OWLAPI/GROUPBOX` and `OWLAPI/EDIT` constructor-overload failures.
- **Proposed acceptance oracle (set at Gate 1):** A test compiles a call with no viable overload and asserts the message contains the formatted argument types and at least the candidate count/signatures; re-running the GROUPBOX/EDIT product probe yields an actionable message rather than a bare name.
