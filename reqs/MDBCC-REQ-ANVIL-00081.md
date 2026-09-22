# MDBCC-REQ-ANVIL-00081 — Resource compiler lacks `-i`/`-r` and rejects `#include <...>` in `.rc` files

- **State:** Draft
- **Priority:** Should
- **Area:** Driver / CLI / project
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
mdrc must accept `-i<dir>` (repeatable) feeding the `.rc` preprocessor's include search, accept `-r` (compile-only, the default) as a no-op alias, and support the `#include <...>` angle form, so stock OWL `.rc` files compile.

## Rationale
mdrc has no `-i<dir>` include-search flag and no `-r` flag, and its `.rc` preprocessor resolves `#include` only relative to the including file while rejecting the angle-bracket `#include <...>` form outright — exactly the form every stock OWL/OCF `.rc` uses.

- **Current:** `mdrc -r -iD:\BC45\INCLUDE foo.rc` fails on `-r` (unknown), has no include search path, and any `.rc` that does `#include <windows.h>` / `<owl/mdi.rh>` fails to preprocess.
- **Expected (BCC 4.52):** BRCC32 accepts `-i<dir>` (repeatable include path, also via `INCLUDE`), `-r` (compile to `.res` only), `-fo<file>`, and `-D`, and resolves both quoted and angle-bracket `#include` directives against the search path.
- **Blocks:** Compiling stock BC4.52 / OWL sample `.rc` files that `#include` system or resource headers (S6 OWL-sample stone).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-01** — severity medium, type missing-feature, effort M, status sharpens-parked.

- **Evidence:** `src/bin/mdrc.rs:70-128` (accepts `-o`/`--out`, `--profile`/`--bc45`, `-D`, partial `-fo`; `-i`/`-r` hit the unknown-option arm at `mdrc.rs:118-120`); `src/rc/pp.rs:62-67` rejects `#include <...>`; `src/rc/pp.rs:69` resolves includes only via `dir.join`; oracle `EXAMPLES/MAKEFILE.GEN:787-788` `.rc.res` rule `$(BRCC) -r -i$(INCLUDEPATH) $$<`.
- **Proposed acceptance oracle (set at Gate 1):** A `.rc` that `#include`s a header (quoted and angle-bracket) found only under `-i<dir>` compiles to a `.res` via mdrc; `-r` is accepted.
