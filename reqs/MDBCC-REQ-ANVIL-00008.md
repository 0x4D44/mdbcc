# MDBCC-REQ-ANVIL-00008 — Stray non-pp-token bytes hard-error instead of emitting `TokenKind::Other`

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
`lex_punct`'s unknown-byte fallthrough shall emit `Token::new(TokenKind::Other(b))` (bumping one byte) for non-white-space bytes that start no other pp-token, instead of returning an error, honouring the documented contract of the `Other` variant.

## Rationale
`lex_punct`'s unknown-byte fallthrough returns a `LexError` for any byte that starts no recognised punctuator, even though `TokenKind::Other` is documented to carry exactly such bytes per C89 6.4; that variant is only ever produced by the `lex_char` rewind, never here, so the documented contract is half-implemented.

- **Current:** A non-pp-token byte at token start (e.g. `$`, `@`, backtick, a lone `\`, or a high-bit OEM byte 0x80-0xFF in `#error` / `#pragma message` free-text) raises a hard `LexError`, aborting preprocessing/compilation.
- **Expected (BCC 4.52):** Per C89 6.4, such a byte is itself a preprocessing token; the preprocessor passes it through as an ordinary token (notably in `#error` and `#pragma message` free-text) rather than aborting. (mdbcc tokenizes and rejoins directive free-text with spaces, so the byte round-trips as a one-character `Other` token, not verbatim line text.)
- **Blocks:** none directly (in-scope headers confine `$`/`@` and high-bit bytes to comments/strings); robustness gap that could surface on real-world C TUs with non-ASCII `#error`/`#pragma` text.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LEX-02** — severity low, type spec-conformance, effort S, status new.

- **Evidence:** `src/lexer.rs:983` (fallthrough `other => { return self.err(...) }`); `TokenKind::Other` defined at `src/lexer.rs:75`, contract documented at `src/lexer.rs:69`-74; only producer is the `lex_char` rewind at `src/lexer.rs:678`. Downstream plumbing already round-trips `Other`: `src/pp.rs:1861` (`spelling()`), free-text tokenized at `src/pp.rs:1068`.
- **Proposed acceptance oracle (set at Gate 1):** A test feeding a bare `$` token and `#error has $ and \xA9 here` through the lexer yields `Other` tokens and no `LexError`; the preprocessor still processes the directive free-text.
