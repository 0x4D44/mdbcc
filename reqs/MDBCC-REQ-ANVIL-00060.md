# MDBCC-REQ-ANVIL-00060 — Lexer ignores wide-string `L"..."` and multi-char int suffixes

- **State:** Draft
- **Priority:** Could
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Recognise an `L`/`l` (and optionally `u`) prefix immediately preceding `"` as a wide-string literal, and have `eat_int_suffix` consume the full `[uUlL]+` suffix run.

## Rationale
The lexer does not recognise an `L` prefix before `"` (it lexes `L` as a separate identifier), and `eat_int_suffix` consumes only a single `L`/`l`, so `UL`/`LL`/`U` suffixes leave a stray identifier.

- **Current:** `L"text"` parses as identifier `L` then a string (a syntax error in any value position); integer literals with `UL`/`LL`/`U` leave a trailing identifier token. Both today fail cleanly rather than miscompiling.
- **Expected (BCC 4.52):** BRC32 accepts `L"..."` wide string literals and the BC4.52 RC dialect's integer suffixes.
- **Blocks:** none (unreachable in the in-scope target; trivial hardening only).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-08** — severity low, type incomplete, effort S, status new.

- **Evidence:** `src/rc/lexer.rs:481` (`lex_string` only on `"`), `src/rc/lexer.rs:307,286,355` (`L` consumed by `lex_ident`), `src/rc/lexer.rs:427-434` (single-char suffix). Corpus scan: no genuine `L"..."` literal and no multi-char `UL`/`LL`/`U` suffix appears in the in-scope oracle; only single-`L` (`0x80L`, `0x1L`) occurs, which is already handled.
- **Proposed acceptance oracle (set at Gate 1):** `CAPTION L"Title"` and a value `0x20UL` both lex without producing a stray identifier and round-trip brc32-clean.
