# MDBCC-REQ-ANVIL-00113 — `switch` lowered as a linear cmp/je chain with no jump-table or range/duplicate-label validation

- **State:** Draft
- **Priority:** Could
- **Area:** Cross-seam / completeness
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add (a) a jump-table lowering for dense integer switches and (b) a duplicate-`case`-constant diagnostic. (Lower priority than GAP-01..05 — correctness holds today.)

## Rationale
`switch` is always a linear comparison cascade; there is no jump-table lowering and (verify) no diagnostic for duplicate `case` constants. Only a performance/correctness-of-validation concern, but OWL message-dispatch-style large switches in RTL/OWL are affected.

- **Current:** A dense N-case switch costs N comparisons; correctness is fine but large switches in hot OWL/RTL paths are slow, and duplicate-case constants are not rejected.
- **Expected (BCC 4.52):** bcc32 emits a jump table for dense switches; duplicate `case` labels are a hard error.
- **Blocks:** Performance of S5/S6 dispatch-heavy code; not a blocker for correctness.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **GAP-06** — severity low, type missing-feature, effort M, status open.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:5800-5860` lowers each case as `eax = Vi; cmp eax,[E]; je Lcase_i` in a loop (`case_jumps`), confirming the O(n)-compare model; no `jmp [table + idx*8]` path exists.
- **Proposed acceptance oracle (set at Gate 1):** A dense 100-case switch emits a table-indexed jump; two identical `case 1:` labels produce a clean error.
