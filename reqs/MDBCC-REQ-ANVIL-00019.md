# MDBCC-REQ-ANVIL-00019 — `int` and `long` mangle to the same symbol, colliding distinct overloads

- **State:** Draft
- **Priority:** Must
- **Area:** C++ semantics (overloads/templates/MI/RTTI)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Carry the source int-vs-long (and unsigned) distinction into `Type` so `borland_mangle_type` emits `i`/`l`/`ui`/`ul` distinctly per Borland's encoding; an `int` overload and a `long` overload must never share a mangled symbol. Re-derive the exact `long`/`unsigned long` code letters against the oracle `.obj` PUBDEF output during the fix rather than assuming `l`/`ul`.

## Rationale
`borland_mangle_type` keys the integer type-code solely on byte width, so 32-bit `int` and `long` (and their unsigned variants) emit identical mangled symbols; one overload silently clobbers the other in the object/library with no diagnostic.

- **Current:** `Type::Int{bytes:4}` mangles to `i`/`ui` whether the source was `int` or `long`; `int fa(int)` + `int fa(long)` both emit `@fa$qi`, and call sites cannot select between them. The AST has no int-vs-long distinction at all (`Type::Int{bytes,signed}` only).
- **Expected (BCC 4.52):** Mangles `int`->`i`, `long`->`l`, `unsigned int`->`ui`, `unsigned long`->`ul` as distinct codes despite both being 32-bit, so `ostream::operator<<(int)` and `operator<<(long)` are separate symbols.
- **Blocks:** Robust iostream/streams usage in OWL samples; linking against any real Borland `.lib` exporting `$l`/`$ul` symbols; correct long-vs-int overload selection generally.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **SEM-01** — severity critical, type abi, effort L, status new.

- **Evidence:** `C:\language\mdbcc\src\codegen\cpp.rs:294-312` (`bytes==4 -> "i"`, unsigned prefixes it); `C:\language\mdbcc\src\parser.rs:1450` collapses `long` to `bytes:4`; oracle `C:\language\mdbcc\wrk_oracle\bc452\BC45\INCLUDE\iostream.h:624-627`.
- **Proposed acceptance oracle (set at Gate 1):** A TU with `f(int)`+`f(long)` (and the unsigned pair) emits two distinct mangled symbols matching `bcc32`; `cout<<anInt` and `cout<<aLong` dispatch their respective `ostream::operator<<` bodies; a round-trip test against `iostream.h`'s six integer `operator<<` overloads links without symbol collision.
