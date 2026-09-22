# MDBCC-REQ-ANVIL-00006 — `__FILE__`/`__LINE__` not updated inside `#include`'d files; `#line` ignored

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
`do_include` must set `self.file` to the resolved header name for the duration of its recursive processing (restoring on return), and `#line` should at minimum update the presumed file/line feeding `__FILE__`/`__LINE__`.

## Rationale
`self.file` is never updated when recursing into an included header and `#line` is dropped, so `__FILE__` used directly inside a header reports the parent TU, `__LINE__` carries no `#line` remapping, and `#line` directives are silently ignored.

- **Current:** Inside an included header, `__FILE__` reports the including TU's filename and `__LINE__` is the header buffer's lexer line with no `#line` adjustment; `#line` remaps are dropped. Note `assert()` is a macro whose `__FILE__`/`__LINE__` expand at the call site, so the common `assert()` path is correct at TU granularity; the genuine breakage is `__FILE__`/`__LINE__` used directly inside a header body, and `#line` remapping for generated/preprocessed sources.
- **Expected (BCC 4.52):** Per X3J11 §6.10.4/§6.10.8, `__FILE__` is the presumed name of the current source file (the header while it is being processed) and `__LINE__` the presumed line, both adjustable by `#line`. bcc32 4.52 reports header filenames in `__FILE__` and diagnostics.
- **Blocks:** Accurate diagnostics and `assert()`/`__FILE__` text fidelity (S3); cosmetic for codegen of the flagship OWL samples (no miscompile).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PP-06** — severity low, type incomplete, effort S, status new.

- **Evidence:** `src/pp.rs:1507-1515` (`__FILE__` always expands to `self.file`, the top-level TU name, set once in `new()` at `:892`); `src/pp.rs:1240-1242` (`do_include` recurses via `self.run(toks)` without saving/setting `self.file`); `src/pp.rs:1109` (`#line` accepted and ignored); `src/pp.rs:1479` (`__LINE__` uses the raw token line, no `#line` remap).
- **Proposed acceptance oracle (set at Gate 1):** A header containing `__FILE__` expands to that header's name, not the TU's; an `assert()` defined and used inside a header records the correct file. Add an include-scoped `__FILE__` test.
