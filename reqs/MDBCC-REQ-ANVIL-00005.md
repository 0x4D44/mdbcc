# MDBCC-REQ-ANVIL-00005 — Computed/indirect includes (`#include MACRO`) unsupported

- **State:** Draft
- **Priority:** Could
- **Area:** Preprocessor
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
When the include operand is neither a literal `"..."` nor `<...>` sequence, macro-expand `rest` and re-parse the result as a header-name — reconstructing `<...>` from `< … >` punct/ident tokens (the defensive path at `src/pp.rs:1213-1221`) and `"..."` from a string token.

## Rationale
`do_include` reads the header name only from the literal `"..."` or `<...>` forms and never macro-expands the operand, so `#include SOME_MACRO` is a hard preprocessor error.

- **Current:** Only `"file"` and `<file>` are accepted; `#include SOME_MACRO` (where the macro expands to a header-name form) is a hard error.
- **Expected (BCC 4.52):** Per X3J11 §6.10.2 p4, when the directive matches neither the `"..."` nor `<...>` form, the remaining tokens are macro-expanded and the result must then match one of those forms. bcc32 4.52 supports this; no `#include MACRO` use exists in the in-scope oracle header tree, so it is practically unreachable on the mission path.
- **Blocks:** Any real TU/header using indirect includes (none found in the BC4.52 corpus, but standard-mandated); low-frequency on the target path.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PP-05** — severity low, type missing-feature, effort S, status new.

- **Evidence:** `src/pp.rs:1197-1224` (`do_include` reads `rest.first()` as a literal `Str` or `<...>` reconstruction; `rest` is never passed through `self.expand(...)`; falls through to the error at `:1223`). The `expand()` infrastructure already exists and is `&self` (`src/pp.rs:1310`).
- **Proposed acceptance oracle (set at Gate 1):** `#define H <stdio.h>` then `#include H` resolves identically to a direct `#include <stdio.h>`; `#define Q "local.h"` / `#include Q` resolves the quoted form. Add a computed-include unit test for both forms.
