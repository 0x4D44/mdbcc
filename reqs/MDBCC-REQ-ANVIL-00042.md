# MDBCC-REQ-ANVIL-00042 — Stale doc comments misdescribe the actual Cleanup-scope coverage

- **State:** Draft
- **Priority:** Could
- **Area:** Exception handling
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Refresh the J-11b/J-15 doc comments to describe the real current coverage and the precise per-target residual, noting that `CatchPolicy::Cleanup` already exists, so the gap boundary is unambiguous.

## Rationale
Load-bearing EH doc comments still describe an earlier "no cleanup scopes at all" state, contradicting the now-wired Win64 Cleanup pads, risking a future maintainer re-implementing existing machinery or mis-scoping an i386 fix.

- **Current:** The J-11b/J-15 comments describe an earlier state, contradicting the wired Win64 Cleanup pads (ctor partial-construction at `4241`, array-new at `16972`). The most concretely wrong line is the J-15 "extend `CatchPolicy`" sentence — that variant already exists.
- **Expected (BCC 4.52):** N/A — documentation accuracy; no behaviour change. Comments should state that Win64 ctor + array-new Cleanup pads are wired and name the exact residuals: (a) ordinary function-scope locals on any target (EH-01) and (b) the entire i386 Cleanup path (EH-02).
- **Blocks:** Accurate auditing; prevents mis-scoped follow-on fixes for EH-01/EH-02.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **EH-06** — severity low, type diagnostics, effort S, status new.

- **Evidence:** `src/codegen.rs:16544-16567` (J-15 doc claims array-new uses "no SEH unwind callback" and proposes adding a Cleanup `CatchPolicy` variant — but `CatchPolicy::Cleanup` exists and is registered at `16972`); `src/codegen.rs:4842-4854` (J-11b doc describes base-dtor cleanup as un-wired though `4241` registers it).
- **Proposed acceptance oracle (set at Gate 1):** Doc comments at `src/codegen.rs:4842` and `16544` reflect the wired Win64 Cleanup pads and name the exact residuals (i386 + non-`try` locals); no code behaviour change.
