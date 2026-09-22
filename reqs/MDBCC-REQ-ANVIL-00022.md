# MDBCC-REQ-ANVIL-00022 — Genuine overload ambiguity between two equal-cost conversions is not always diagnosed

- **State:** Draft
- **Priority:** Should
- **Area:** C++ semantics (overloads/templates/MI/RTTI)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
After fixing SEM-01/02/03, ensure two distinct candidates with truly equal conversion ranks produce an ambiguity diagnostic and never silently dispatch by declaration order. (Composite: depends on the mangling/ranking fixes.)

## Rationale
A real `{int, long}` tie is routed into the "same function" arm (because the two collapse to one identical `Type` value and one mangled symbol), silently keeping the first-declared candidate as a redeclaration instead of resolving by rank or reporting ambiguity.

- **Current:** `f(int)`/`f(long)` collapse to a single candidate at the dedup; the call silently dispatches to the first-declared overload with no ambiguity diagnostic, even though the real RTL bodies differ in width/formatting.
- **Expected (BCC 4.52):** Either resolves by conversion rank or, when two distinct candidates have indistinguishable conversion sequences, emits an "ambiguous" diagnostic — it never silently picks one of two genuinely tied distinct overloads.
- **Blocks:** Predictable diagnostics; prevents silent wrong-callee masquerading as a redeclaration.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **SEM-04** — severity medium, type spec-conformance, effort S, status new.

- **Evidence:** equal-score branch `C:\language\mdbcc\src\codegen.rs:14472-14508`; params-equality dedup `C:\language\mdbcc\src\codegen.rs:1693-1695`; identical `Type` at `C:\language\mdbcc\src\ast.rs:51`, `C:\language\mdbcc\src\parser.rs:1450`; oracle `iostream.h:626-627`.
- **Proposed acceptance oracle (set at Gate 1):** A constructed genuine-ambiguity case (e.g. an arg convertible equally to two unrelated class params via UDC) reports "ambiguous call"; the `int`/`long` case resolves (not ambiguous) once distinct ranks exist.
