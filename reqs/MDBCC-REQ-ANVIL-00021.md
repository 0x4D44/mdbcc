# MDBCC-REQ-ANVIL-00021 — `arg_compat` rejects all integer↔floating conversions

- **State:** Draft
- **Priority:** Must
- **Area:** C++ semantics (overloads/templates/MI/RTTI)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Admit integer↔floating conversions as ranked conversion sequences (`float`->`double` as promotion; other crossings as conversion), added as a new ranked branch in the scoring loop ABOVE the `arg_compat` fallthrough at `C:\language\mdbcc\src\codegen.rs:14441` and ranked worse than score 0/1 exact-arithmetic matches so existing int-exact-wins baselines stay byte-identical.

## Rationale
`arg_compat` returns `Some` only for ref-exact, equal, integer/integer, and pointer/pointer; a float param vs int arg (or int param vs float arg) falls through to `None`, so any overload requiring an int/float crossing is dropped and a float-only overload set called with an integer literal is wrongly rejected.

- **Current:** `int sq(double)+int sq(char*); sq(3)` -> error `no matching overload`; `int fa(int)+int fa(double); fa(aFloat)` -> error `no matching overload`. A non-overloaded `double sq(double)` called with `sq(3)` compiles, proving the conversion exists at the call site.
- **Expected (BCC 4.52):** Treats `int`->`double` / `float`->`int` as a valid floating-integral standard conversion and `float`->`double` as a promotion; `sq(3)` selects `sq(double)` over `sq(char*)`, and `fa(aFloat)` selects `fa(double)` over `fa(int)`.
- **Blocks:** Overloaded math/stream helpers taking `double`/`float` when called with integer literals; general arithmetic overload sets in RTL/OWL.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **SEM-03** — severity high, type bug, effort M, status new.

- **Evidence:** `C:\language\mdbcc\src\codegen\cpp.rs:460-484`; single-candidate conversion works at `C:\language\mdbcc\src\codegen.rs:12189` / `12202`, confirming the gap is in overload scoring, not codegen.
- **Proposed acceptance oracle (set at Gate 1):** `int sq(double)+int sq(char*); sq(3)` compiles and runs `sq(double)`; `fa(int)+fa(double)` with a float arg selects `fa(double)`; the existing `overload_by_type_int_vs_double` / int-exact-wins cases are unchanged.
