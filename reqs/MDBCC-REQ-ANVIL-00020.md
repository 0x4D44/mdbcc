# MDBCC-REQ-ANVIL-00020 — `arg_compat` cannot distinguish integral promotion from integral conversion

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
Rank conversion sequences so Exact > Promotion > Conversion, with promotion defined as `char`/`short`/`bool`/`enum` -> `int`/`unsigned int` and `float` -> `double`; the chosen overload must be declaration-order-independent.

## Rationale
Every integer→integer match scores a flat `1` (exact-equal is `0`) with no `[over.ics.rank]` promotion>conversion ordering and no width preference, so a `char` argument among `{int, short}` candidates produces a spurious hard ambiguity error instead of selecting `int` by promotion.

- **Current:** `char`/`short` args score identically against `int` and `long` candidates. For distinct-symbol candidates the equal-score branch sets `ambiguous=true` and emits an "ambiguous call to overloaded" error rather than ranking. (The `f(int)`/`f(long)` repro is masked by SEM-01's symbol collapse; the rank gap is independent.)
- **Expected (BCC 4.52):** Ranks an integral promotion (`char`/`short`/`bool`/`enum` -> `int`/`unsigned`) above an integral conversion, so `f(char)` deterministically selects the `int` overload over `long`/`short`, independent of declaration order.
- **Blocks:** Deterministic, conformant overload selection for code overloading on integer/float widths; trust in `resolve_overload` for OWL/RTL.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **SEM-02** — severity high, type bug, effort M, status new.

- **Evidence:** `C:\language\mdbcc\src\codegen\cpp.rs:466-482`; ambiguity branch at `C:\language\mdbcc\src\codegen.rs:14503-14504`.
- **Proposed acceptance oracle (set at Gate 1):** `f(char)` among a width-distinct pair (e.g. `{int, short}` or `{int, unsigned}`, not the SEM-01-collapsing `{int, long}`) selects `int` regardless of declaration order; a regression fixture swaps declaration order and asserts identical runtime result matching `bcc32`. Land alongside or after SEM-01's width-distinct mangling fix.
