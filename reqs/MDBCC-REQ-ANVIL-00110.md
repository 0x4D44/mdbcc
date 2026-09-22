# MDBCC-REQ-ANVIL-00110 — No floating-point compile-time constant evaluation for global initializers

- **State:** Draft
- **Priority:** Should
- **Area:** Cross-seam / completeness
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add floating-point constant folding (or extend the dynamic-init fallback to `Type::Float`) so file-scope `float`/`double` globals with folded or runtime initializers initialize correctly.

## Rationale
`const_eval` is integer-only, and the codegen dynamic-init fallback is gated to `Type::Int` / `Type::Ptr`, so a file-scope floating-point global with a folded or non-literal initializer has no working path. PP-04 covers only the *preprocessor* `#if` i64 evaluator — a different evaluator.

- **Current:** `static double x = 1.0/3.0;` / `const double K = 2*PI;` cannot fold and is not caught by the dynamic-init fallback → `global_image` error (or only a bare single-literal `Expr::Float` survives).
- **Expected (BCC 4.52):** bcc32 folds floating constant-expression initializers at compile time; non-constant FP global initializers run as dynamic init.
- **Blocks:** S3/S5 — RTL/BIDS/OWL headers and sources use folded FP constants in file-scope initializers.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **GAP-03** — severity medium, type missing-feature, effort M, status open.

- **Evidence:** `C:\language\mdbcc\src\parser.rs:9495` — `pub fn const_eval(e: &Expr) -> Option<i64>` (no float arm; `Expr::Float` is not handled). The codegen scalar dynamic-init fallback is guarded `matches!(ty, Type::Int { .. })` at `C:\language\mdbcc\src\codegen.rs:1313` and `matches!(ty, Type::Ptr(_))` at `:1390` — `Type::Float` is excluded from both, falling through to `global_image` at `:1343`.
- **Proposed acceptance oracle (set at Gate 1):** `static double h = 1.0/2.0;` and `static double r = some_global_double;` produce the correct stored/initialized value at runtime on both targets.
