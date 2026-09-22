# MDBCC-REQ-ANVIL-00004 — `#if` constant-expression evaluator is signed-`i64`-only

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
`CondEval` must track signedness per operand (seeded from the `Int` token's `unsigned` flag and U/L suffixes), apply usual-arithmetic-conversions (unsigned wins), and perform unsigned division/modulo, logical right-shift, and unsigned relational comparisons when either operand is unsigned.

## Rationale
`CondEval` discards each operand's unsignedness and evaluates `#if`/`#elif` purely in signed `i64`, so unsigned comparison, division/modulo, and logical right-shift are not implemented and U/L suffixes are ignored — diverging from the already-fixed compiler `const_eval`.

- **Current:** Every `#if`/`#elif` sub-expression is evaluated signed: `#if -1 > 0u` is false where C requires true, `#if (0u-1) >> 8` shifts arithmetically, `#if 0x80000000u / 2u` divides signed, and U/UL/ULL suffixes are ignored in conditionals.
- **Expected (BCC 4.52):** Per X3J11 §6.6/§6.10.1, `#if` expressions follow the usual arithmetic conversions — an unsigned operand or result makes the operation unsigned (logical shift, unsigned compare/divide/modulo). bcc32 4.52 follows this; no in-scope oracle guard currently triggers the divergence (all use small positive constants), but it is a genuine conformance gap.
- **Blocks:** Correct evaluation of unsigned/version guards in real BC4.52 + Win32 headers (S3); consistency with the already-fixed compiler `const_eval`; rare silent-wrong-branch selection (no demonstrated trigger on any in-scope path today).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PP-04** — severity medium, type spec-conformance, effort M, status sharpens-parked.

- **Evidence:** `src/pp.rs:2040-2047` (`CondEval::unary` drops the `unsigned` field present at `src/lexer.rs:52`: `Some(TokenKind::Int { value, .. }) => Ok(value as i64)`); `src/pp.rs:2110-2145` (`apply` is i64-only: `Slash => a.wrapping_div(b)`, `Shr => a.wrapping_shr(...)` arithmetic, `Lt => (a<b)` signed); contrast `BUGS.md` F-09 (compiler `const_eval` fixed to fold unsigned `>>` logically).
- **Proposed acceptance oracle (set at Gate 1):** `#if -1 > 0u` takes the true branch; `#if (0u-1) >> 31 == 1` is true (logical shift); `#if 0x80000000u/0x10000u == 0x8000` is true. Add a pp `#if` unit-test matrix mirroring the `const_eval` F-09 regression cases.
