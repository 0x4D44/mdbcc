# MDBCC-REQ-ANVIL-00102 — Multiple 1000+ LOC god-functions in codegen.rs

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
Extract `compile_module_for`'s pre-passes (monomorphize, winmain-dedup) into named functions returning a normalized TU, then a single emit pass; split the large arms of `gen_expr`/`gen_stmt_inner` (call marshaling, new/delete, EH) into their own methods.

## Rationale
Several codegen functions exceed any reasonable cyclomatic budget; `compile_module_for` interleaves three unrelated passes and re-enters itself by clone-and-recurse, while `gen_expr`/`gen_stmt_inner` are giant single-`match` dispatchers where a bug in one arm sits amid 1000+ sibling lines.

- **Current:** A driver function inlines named passes instead of orchestrating them; expression/statement lowering is a single huge body rather than dispatchable units.
- **Expected (BCC 4.52):** Internal maintainability requirement: a driver should orchestrate named passes; lowering arms should be dispatchable methods.
- **Blocks:** none (raises review friction on the exact functions the parked EH/long-double/divide fixes must edit, but does not gate them).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-02** — severity medium, type tech-debt, effort L, status new.

- **Evidence:** In `src/codegen.rs`: `compile_module_for` (line 802) = 1927 lines, mixing template monomorphization (812–825) and WinMain dedup (839–856) — each via a full `tu.clone()` + tail-recursion — with inline symbol collection and emission; `gen_expr` (9322) = 1229; `gen_stmt_inner` (4987) = 1047; `run` (3678) = 743; `expr_type` (18668) = 550; `gen_libc` (13631) = 525; `float_token` (18134) = 492; `gen_delete` (16066) = 458; `gen_new_array` (16569) = 431.
- **Proposed acceptance oracle (set at Gate 1):** The extracted base/member/EH/call-marshaling units are individually reviewable and `compile_module_for` reduces to orchestration over named passes; baselines stay byte-identical. (The "~300 LOC" cap is a style target the repo has not adopted as a stated requirement.)
