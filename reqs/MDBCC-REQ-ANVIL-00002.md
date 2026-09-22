# MDBCC-REQ-ANVIL-00002 — Stringification (`#`) does not escape embedded quotes/backslashes and loses source spacing

- **State:** Draft
- **Priority:** Must
- **Area:** Preprocessor
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
`stringize` must (a) separate two tokens with a space only when they were non-adjacent in the source (computable from line/col), and (b) escape `\` and `"` within stringified string/char literals; the `Char`/`Str` spelling used for `#` must reproduce the original lexeme faithfully.

## Rationale
`stringize` joins tokens with an unconditional single space regardless of source adjacency, and re-quotes string/char literals without escaping inner `"` or `\`, so any argument containing a literal produces invalid C and assertion text is corrupted.

- **Current:** `#x` inserts a space between every token (`STR(a+b)` yields `"a + b"`), and an argument with a literal yields invalid C — `STR("hi")` produces unescaped `""hi""`, which re-lexes wrong or breaks the surrounding substitution. `assert()` of an expression containing a string/char literal is corrupted; `Char` spelling additionally truncates wide/escaped chars.
- **Expected (BCC 4.52):** Per X3J11 §6.10.3.2, white space between argument tokens collapses to a single space and is deleted at the ends, no space is inserted where the source had none, and each `\` and `"` in the spelling of a string/char literal is preceded by a `\`. bcc32 4.52 produces source-faithful, properly escaped assertion strings.
- **Blocks:** Correct `assert()`/diagnostic macro text (S3/S4 C++ dialect parity); any header macro that stringizes an expression containing literals; prevents invalid re-lexed tokens entering the parser.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PP-02** — severity high, type spec-conformance, effort M, status new.

- **Evidence:** `src/pp.rs:1819-1828` (`stringize` always inserts a single space: `if i>0 { s.push(' ') }`); `src/pp.rs:1853-1856` (`spelling` of a `Str` token re-quotes raw bytes with no escaping; `Char` truncates via `(value as u8) as char`); re-wrapped at `src/pp.rs:1768`; oracle `ASSERT.H:82` stringizes the predicate via `#p`.
- **Proposed acceptance oracle (set at Gate 1):** `#define S(x) #x` gives `S(a+b)=="a+b"`, `S(a == b)=="a == b"`, and `S("x\n")=="\"x\\n\""` (a valid C string literal); `assert` with a string-literal argument compiles and its recorded text matches bcc32. Add a stringize unit test covering spacing and embedded-literal escaping.
