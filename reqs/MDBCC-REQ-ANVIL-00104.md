# MDBCC-REQ-ANVIL-00104 — Untyped AST forces `expr_type` re-derivation at 130 call sites

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
Introduce a single type-resolution seam (annotate `Expr` or memoize `expr_type` per node) so codegen consults resolved types instead of re-deriving them, without changing emitted bytes. Note: `Expr` is referenced as `&Expr` with no stable node id, so a memo needs pointer-identity or an index pass — a design constraint for the implementer.

## Rationale
`Expr` carries no resolved-type field, so codegen's recursive 550-LOC `expr_type` is invoked 130 times to recompute types the call site often already needs — a perf cost on large TUs and a correctness footgun where lowering and typing encode the same rule twice and can drift.

- **Current:** Type information is recomputed on demand throughout codegen rather than resolved once; rules that must agree between lowering and typing (literal widths, overload selection, op64 width) are encoded twice.
- **Expected (BCC 4.52):** BCC 4.52 type-checked internally before codegen; mdbcc's untyped-AST-then-recompute is a known shortcut. Provide either a typed-AST annotation pass or a per-node memoized type cache — O(1) and single-source-of-truth.
- **Blocks:** none (affects perf on S5/S6 OWL builds and the long-double/width work where typing and lowering must agree, but is not a present miscompile).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-04** — severity medium, type tech-debt, effort L, status new.

- **Evidence:** `src/ast.rs` `enum Expr` (line 722) has no type field (comment at `ast.rs:44` confirms no annotation map exists); `src/codegen.rs` `fn expr_type` (line 18668, ~550 LOC, recursive) is called 130× (`grep "expr_type(" src/codegen.rs` = 130). A past width/typing miscompile is documented at `codegen.rs:11383-11385`.
- **Proposed acceptance oracle (set at Gate 1):** `expr_type` is no longer called redundantly within a single lowering of an expression tree (memo hit or annotation); baselines byte-identical; large-TU compile time does not regress.
