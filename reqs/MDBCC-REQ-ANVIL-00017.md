# MDBCC-REQ-ANVIL-00017 — Dependent non-type template parameter `template<class T, T value>` fails (parked deeper-dependent syntax)

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
Register each type parameter as a type name incrementally as it is parsed (before the next parameter), so later parameters' types and defaults can reference it.

## Rationale
Type parameters are registered as type names only after the entire parameter list is parsed, so a later parameter whose type or default depends on an earlier type parameter cannot resolve it.

- **Current:** `template<class T, T value> ...` (or a non-type default referencing an earlier param such as `= sizeof(T)`) fails with a spurious unknown-type error.
- **Expected (BCC 4.52):** Each template parameter is in scope for all subsequent parameters' types and defaults within the same parameter list. (No CLASSLIB/INCLUDE template uses a dependent non-type parameter or a default referencing an earlier param, so this is latent.)
- **Blocks:** none in scope; robustness for fuller template parity. Tracked as parked deeper-dependent-template syntax in `BUGS.md:45-46`.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSX-03** — severity low, type incomplete, effort M, status sharpens-parked.

- **Evidence:** `C:\language\mdbcc\src\parser.rs:4944-5004` parses all parameters first; type-parameter registration to `Type::TemplateParam` happens only afterward at `C:\language\mdbcc\src\parser.rs:5076-5086`. A non-type parameter `T value` calls `self.decl_specifiers()?` at `C:\language\mdbcc\src\parser.rs:4957` before `T` is known, so `T` resolves as an unknown ident and falls into the hard `expected a type` error.
- **Proposed acceptance oracle (set at Gate 1):** `template<class T, T value> ...` parses without a spurious unknown-type error; existing function/class template baselines stay byte-identical. Add a parser unit test for the dependent non-type param form.
