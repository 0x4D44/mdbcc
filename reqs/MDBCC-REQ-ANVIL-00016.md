# MDBCC-REQ-ANVIL-00016 — Default template arguments are parsed and dropped, so omitting a defaulted parameter is rejected

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
Record default template arguments (type and non-type) on the template-decl and substitute them for trailing omitted arguments during instantiation arity resolution.

## Rationale
Default template arguments (both type and non-type) are consumed and discarded, never stored on the template-decl, so instantiation arity checking has no fallback for a trailing omitted argument.

- **Current:** `template<class T, class A = DefAlloc> struct Box{...}; Box<int> b;` errors `class template Box expects 2 type argument(s), got 1`.
- **Expected (BCC 4.52):** BC4.52 applies the declared default for any trailing omitted template argument. (The in-scope BIDS corpus avoids this by naming the allocator in explicit wrapper classes, e.g. `TVectorImp<T> : public TMVectorImp<T,TStandardAllocator>`; a grep of the whole BC45 INCLUDE tree found no `=` default in any template parameter list, so this is latent.)
- **Blocks:** none today (corpus spells out all args); would block future OWL/3rd-party C++ TUs using defaulted template params.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSX-02** — severity low, type incomplete, effort M, status new.

- **Evidence:** `C:\language\mdbcc\src\parser.rs:4994-4996` discards a default TYPE arg (`if self.eat_punct(Assign) { let _ = self.type_name()?; }`); `C:\language\mdbcc\src\parser.rs:4972-4974` discards a default NON-TYPE arg (`let _ = self.assignment()?;`); the strict-equality arity check at `C:\language\mdbcc\src\parser.rs:5567` has no default-fallback.
- **Proposed acceptance oracle (set at Gate 1):** `template<class T, class A = X> struct Box{...}; Box<int> b;` instantiates with `A=X`; existing single-arg/explicit-arg instantiations stay byte-identical. Guard with a parser + instantiation test.
