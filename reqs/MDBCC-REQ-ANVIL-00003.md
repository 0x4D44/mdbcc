# MDBCC-REQ-ANVIL-00003 — `.rc` preprocessor lacks `#include <...>` (and `#if`/`#elif`)

- **State:** Draft
- **Priority:** Should
- **Area:** Preprocessor
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Extend `src/rc/pp.rs` to support `#include <...>` resolved via a resource include search path (the BC4.52 `INCLUDE/` root, e.g. `<owl\owlapp.rc>` → `INCLUDE/owl/owlapp.rc`) with transitive expansion; defer `#if`/`#elif`/`defined()` until an in-scope `.rc` demonstrably needs it, then reuse the rc expression evaluator.

## Rationale
The resource preprocessor rejects the angle-bracket `#include <...>` form (and has no `#if`/`#elif`/`defined()` or function-like macros), yet effectively every OWL example `.rc` includes system headers via angle brackets, so those scripts cannot be preprocessed.

- **Current:** The `.rc` preprocessor evaluates only `#ifdef`/`#ifndef`/`#else`/`#endif` and substitutes object macros; `#include <...>` is rejected as ill-formed, and `#if`/`#elif` are unknown directives. railc golden output uses only the quoted include form.
- **Expected (BCC 4.52):** Borland BRC32 runs a fuller C-like preprocessor over `.rc` scripts, including angle-bracket system includes resolved off the resource include search path (real OWL `.rc` files commonly do `#include <owl\owlapp.rc>`). The `#if`/`#elif` half is not substantiated by any in-scope `.rc` input and should be deferred.
- **Blocks:** S6 OWL sample resource scripts that include system headers (universal across the OWL `.rc` corpus); not blocking railc itself, and produces a clean error rather than a silent miscompile.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PP-03** — severity medium, type incomplete, effort M, status new.

- **Evidence:** `src/rc/pp.rs:46-106` (directive match handles only define/include/ifdef/ifndef/else/endif/undef; errors on anything else at `:104-105`); `src/rc/pp.rs:62-67` (`#include` errors on the non-quoted form); deliberate subset documented at `src/rc/pp.rs:1-18`. OWL examples (POPUP, GAUGEX, …) all do `#include <owl\owlapp.rc>`, which chains transitively to `<owl/window.rh>`.
- **Proposed acceptance oracle (set at Gate 1):** An OWL example `.rc` with `#include <owl\owlapp.rc>` preprocesses (icon plus transitive `window.rh` defines pulled in) with railc golden output unchanged; add an rc-pp test for an angle include resolved off a configured include root.
