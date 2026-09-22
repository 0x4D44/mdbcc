# MDBCC-REQ-ANVIL-00059 — Mis-scoped parked entry B-19 hides the real RC gaps

- **State:** Draft
- **Priority:** Should
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Update the `BUGS.md` RC parked entry to enumerate the concrete remaining gaps (RC `#if`/`defined`, include search path/`<>` form, full style-symbol resolution, missing shorthand controls, CURSOR) with `file:line`, and note that DIALOGEX/DLGTEMPLATEEX has 0 occurrences in the BC4.52 oracle so it is out of scope rather than "pending support".

## Rationale
`BUGS.md` B-19 asserts RC preprocessing/includes/conditionals and style expressions "all pass existing tests" with only DIALOGEX missing, but that is true only for the narrow RailC profile — RC-01 through RC-06 show the OWL surface is unsupported. The Open tables are empty, so these gaps are tracked nowhere.

- **Current:** The ledger frames RC as essentially complete bar DIALOGEX, masking the real S6 blockers (preprocessor `#if`, include paths, style vocabulary, control set, CURSOR).
- **Expected (BCC 4.52):** Not applicable — this is a ledger-accuracy item. The parked entry should record the actual remaining gaps so the OWL-from-source effort is not mis-estimated.
- **Blocks:** none (planning/estimation accuracy for S6).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-07** — severity medium, type tech-debt, effort S, status sharpens-parked.

- **Evidence:** `BUGS.md:55-59`; counter-evidence is findings RC-01–RC-06. `grep -ril DIALOGEX` over EXAMPLES+INCLUDE = 0, confirming DIALOGEX is genuinely out of scope and correctly deferred.
- **Proposed acceptance oracle (set at Gate 1):** The `BUGS.md` RC entry lists the above gaps with `file:line` and the DIALOGEX out-of-scope justification, and no longer claims general preprocessing/style completeness.
