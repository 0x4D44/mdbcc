# MDBCC-REQ-ANVIL-00015 — Explicit specialization `template<> struct S<int>` clobbers the primary template

- **State:** Draft
- **Priority:** Could
- **Area:** Parser — C++ language
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Detect explicit specialization (empty `template<>` param list, or specialization-args after the tag) and emit a clean dedicated `explicit template specialization is not supported` error rather than registering a corrupt 0-param entry that overwrites the primary.

## Rationale
A `template<>`-prefixed explicit specialization is parsed as a 0-parameter class template; its `<int>` specialization-args are swallowed and its registration overwrites the primary template's entry, corrupting every later instantiation of that tag.

- **Current:** `template<class T> struct S{...}; template<> struct S<int>{...}; S<int> a;` errors `class template S expects 0 type argument(s), got 1`; `S<char>` (which should use the primary) fails identically because the primary entry is gone.
- **Expected (BCC 4.52):** BC4.52 supports explicit specialization. Minimum acceptable for the in-scope subset: detect a leading `template <>` (or a tag followed by `<...>` spec-args at capture) and reject it with a clean dedicated diagnostic, without clobbering the primary's registration. (Verified zero `template<>` uses in `wrk_oracle/bc452/BC45/{INCLUDE,SOURCE}`, so full support is out of scope.)
- **Blocks:** none (no in-scope corpus use); prevents a future silent-correctness trap if explicit specialization is ever added to the target set.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSX-01** — severity low, type spec-conformance, effort S, status new.

- **Evidence:** `C:\language\mdbcc\src\parser.rs:4945` (empty `template<>` list skips the param loop, yielding 0 params); `C:\language\mdbcc\src\parser.rs:5374-5448` (body-scan loop advances over the tag and trailing `<int>` spec-args, then `C:\language\mdbcc\src\parser.rs:5439` does `class_template_idx.insert(tag, idx)`, overwriting the prior 1-param primary).
- **Proposed acceptance oracle (set at Gate 1):** A TU with `template<class T> struct S{}; template<> struct S<int>{};` followed by `S<char> a;` either compiles or errors cleanly for the specialization line only; the primary's instantiation for unrelated args is unaffected (no `expects 0 type argument(s)` regression). Add a parser unit test asserting the dedicated diagnostic.
