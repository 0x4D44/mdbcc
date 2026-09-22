# MDBCC-REQ-ANVIL-00018 — `namespace`/`using` are lexed but unhandled, giving a misleading `expected a type` error

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
Recognize a leading `namespace`/`using` at namespace and class scope and emit a dedicated, self-explanatory unsupported-construct diagnostic (still an error).

## Rationale
Both keywords are reserved by the lexer but matched nowhere in the parser, so a namespace definition, using-directive, or using-declaration falls through to the type path and yields a generic, misleading diagnostic.

- **Current:** `namespace N { int x; }` errors `expected a type, found Keyword(Namespace)`; `using namespace std;` errors `expected a type, found Keyword(Using)`.
- **Expected (BCC 4.52):** Namespaces and using are genuinely out of scope for the BC4.52-era OWL/RTL/BIDS surface (the only in-scope INCLUDE hits use `namespace` in comments/field names like `dwNameSpace`, never the keyword). Acceptable behaviour is a clean, explicit `namespaces/using are not supported (BC4.52 dialect)` diagnostic rather than `expected a type`.
- **Blocks:** none (out of scope by mission); improves error quality only.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSX-04** — severity low, type diagnostics, effort S, status new.

- **Evidence:** Lexer reserves the keywords at `C:\language\mdbcc\src\lexer.rs:137` (Namespace) and `C:\language\mdbcc\src\lexer.rs:151` (Using); the parser never matches `Keyword::Namespace`/`Keyword::Using`, so `external_declaration` at `C:\language\mdbcc\src\parser.rs:5952` falls through `decl_specifiers` to the type-expectation error at `C:\language\mdbcc\src\parser.rs:1397`.
- **Proposed acceptance oracle (set at Gate 1):** `namespace N {}` and `using namespace X;` produce a diagnostic that names the unsupported construct; no in-scope corpus TU changes behaviour. Add a parser unit test for each form.
