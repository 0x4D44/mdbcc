# MDBCC-REQ-ANVIL-00009 — RC lexer mis-parses octal integers and carries a stale doc-comment

- **State:** Draft
- **Priority:** Could
- **Area:** Lexer / tokens / literals
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Either parse leading-zero RC integers as octal (matching brc32) or document why decimal-only is acceptable for the in-scope corpus; and correct the stale doc-comment at `src/rc/lexer.rs:8`-9 to note `L`/`l` suffix handling.

## Rationale
The RC number lexer has no octal arm, so a leading-zero literal like `0777` is parsed as decimal `777` (not octal `511`), and the module doc-comment wrongly states integer suffixes are unsupported when the `L`/`l` suffix is in fact consumed.

- **Current:** A leading-zero RC integer is lexed as decimal; the doc-comment incorrectly claims integer suffixes are unsupported.
- **Expected (BCC 4.52):** brc32/rc.exe accept C-style integer constants in expressions, where a leading-zero literal is octal; the doc should reflect that the `L` suffix is consumed.
- **Blocks:** none (in-scope Borland `.rc` files use decimal/hex IDs and flag constants, not octal integer literals).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LEX-03** — severity low, type tech-debt, effort S, status new.

- **Evidence:** Stale doc at `src/rc/lexer.rs:8`-9 ("v1 does not need octal/binary/suffixed integers"); `L`/`l` suffix actually handled via `eat_int_suffix` (`src/rc/lexer.rs:430`, called at `src/rc/lexer.rs:399` and `src/rc/lexer.rs:419`); `lex_number` (`src/rc/lexer.rs:380`) scans hex and a decimal `is_ascii_digit` loop (`src/rc/lexer.rs:409`) with no octal arm.
- **Proposed acceptance oracle (set at Gate 1):** A unit test pins the chosen behaviour for `0777`, the doc-comment matches the code, and existing RC lexer tests still pass.
