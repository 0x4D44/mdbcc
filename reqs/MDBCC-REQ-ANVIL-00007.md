# MDBCC-REQ-ANVIL-00007 — Wide-literal escape sequences truncated to 8 bits

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
`lex_escape` shall yield a value at least 16 bits wide, and the wide-literal paths (`lex_char` / `lex_string_body` when `wide:true`) shall preserve escape values above 0xFF; only narrow literals mask to 8 bits. Note the fix is non-trivial: the wide string body currently stores `Vec<u8>` and re-derives UTF-16 by byte-doubling, so it must also adopt a wide-aware representation (e.g. `Vec<u16>`), not merely drop the `& 0xff`.

## Rationale
`lex_escape` returns a single `u8` and both the octal and hex arms mask the accumulated value with `& 0xff`, so an escape above 0xFF in a wide `L'...'` / `L"..."` literal silently loses its high bits before UTF-16 encoding.

- **Current:** An octal or `\xHH..H` escape inside a wide literal is masked to one byte, so `L'\x263A'` lexes to `0x3A` rather than `0x263A`.
- **Expected (BCC 4.52):** An escape in a wide literal denotes a full 16-bit `wchar_t` value (oracle `stddef.h:56` confirms 16-bit `wchar_t`); `\x` consumes all hex digits and the value is preserved up to `wchar_t` width, so `L'\x263A'` is `0x263A`.
- **Blocks:** none (no in-scope BC4.52 OWL/RTL/BIDS source uses wide escapes above 0xFF; latent lexical-fidelity gap only).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LEX-01** — severity low, type incomplete, effort S, status new.

- **Evidence:** `src/lexer.rs:815` (`fn lex_escape(&mut self) -> Result<u8, LexError>`), octal arm `src/lexer.rs:877` (`(val & 0xff) as u8`), hex arm `src/lexer.rs:892` (`(val & 0xff) as u8`); called identically for wide and narrow at `src/lexer.rs:685` (lex_char) and `src/lexer.rs:806` (lex_string_body); downstream `src/parser.rs:8349` (`utf16le_with_nul`) zero-extends each byte.
- **Proposed acceptance oracle (set at Gate 1):** A lexer unit test asserts `L'\x263A'` lexes to `Char{value:0x263A,wide:true}` and `L"\x263A"` to a wide `Str` whose UTF-16LE encoding contains `0x263A`; existing narrow-escape tests still pass.
