# MDBCC-REQ-ANVIL-00023 — Bare `typeid(x)` yields no real `type_info&` object

- **State:** Draft
- **Priority:** Could
- **Area:** C++ semantics (overloads/templates/MI/RTTI)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Provide a real Borland typeinfo object layout and bare-`typeid` lowering so `typeid(a)==typeid(b)` and `type_info&` parameters work, and align `.name()` to the `bcc32` format. (Sharpens the parked item: the blocker is the typeinfo ABI object, not just the operator.)

## Rationale
A bare `typeid(x)` (used as a `type_info&` for `==`, `before()`, or as an argument) is a clean compile error; only `.name()` (non-`bcc32` format) and polymorphic `.tpp` (vptr substitution, not the real Borland tpp address) shims exist, with no `type_info` `operator==`/`before()`.

- **Current:** Bare `typeid(x)` is `CodegenError('typeid / RTTI is not yet implemented in codegen (S4.5)')`; `.name()` returns a non-`bcc32` string; `.tpp` returns the vptr, not the real tpp address.
- **Expected (BCC 4.52):** Yields a real `const type_info&` with a Borland typeinfo object layout (vptr + tpp) supporting `==`, `!=`, `before()`, and `bcc32`-format `name()`.
- **Blocks:** Full RTTI parity (S4.5). Nothing on the current mission path — the in-scope BC45/OWL corpus uses `typeid` only for `.name()`/`.tpp`.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **SEM-05** — severity low, type missing-feature, effort L, status sharpens-parked.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:9328-9335` (bare-form error), `9399-9412` (`.tpp` vptr substitution); `.name()`-format note at `C:\language\mdbcc\src\codegen.rs:523-531`; parked at `BUGS.md:41-44`.
- **Proposed acceptance oracle (set at Gate 1):** `typeid(a)==typeid(b)` and a `const type_info&` argument compile and behave like `bcc32` on a polymorphic hierarchy; a `name()` string matches the `bcc32` reference for a sample type.
