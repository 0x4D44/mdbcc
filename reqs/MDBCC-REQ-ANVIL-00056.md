# MDBCC-REQ-ANVIL-00056 — Style expressions support only `|` (no `NOT`/parentheses/`& + -`)

- **State:** Draft
- **Priority:** Must
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Extend the style-expression grammar to a constant-expression sub-parser, leading with the must-have `NOT` keyword (clears the following bits) and generalising to `( )` and `| & + -`, matching brc32 semantics.

## Rationale
Style expressions are a flat `term (| term)*`; the `NOT` operator, parentheses, and `& + -` are unsupported. `NOT` appears in 6+ in-scope OWL sample `.rc` files, and parenthesised composite-style macros (e.g. `WS_OVERLAPPEDWINDOW`) cannot be consumed.

- **Current:** A parenthesised expansion fails at the lexer (`unexpected character '('`); `NOT` lexes as an Ident rejected as `unknown style symbol`. Related: `SS_CENTER`/`SS_RIGHT`/`SS_LEFT` used alongside `NOT` are also absent from the table.
- **Expected (BCC 4.52):** BRC32 evaluates full integer constant expressions in style position — the `NOT` operator (clears the following bits), parentheses, and `| & + -` — since after preprocessing a style is just a C constant expression.
- **Blocks:** S6 OWL dialogs that reference `NOT`-bearing or composite style macros.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-04** — severity high, type incomplete, effort M, status new.

- **Evidence:** `src/rc/parser.rs:1412-1445` (only `TokenKind::Pipe`, Int/Ident terms); `src/rc/pp.rs:160-164` (text-substitution of parenthesised macro); oracle uses of `NOT` in `PALETTEX.RC`, `VALIDATX.RC` (`SS_CENTER|RIGHT | NOT WS_GROUP`), `VBXCTLX.RC`, `OWLSCRN.RC`, `SWAT.RC`/`SWAT2.RC`.
- **Proposed acceptance oracle (set at Gate 1):** `CONTROL ... , WS_CHILD | WS_VISIBLE NOT WS_GROUP, ...` parses with the NOT'd bit cleared; `STYLE WS_OVERLAPPEDWINDOW` expanding to a parenthesised OR-chain parses to the correct `u32`.
