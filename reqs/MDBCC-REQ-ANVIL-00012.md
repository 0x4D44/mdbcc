# MDBCC-REQ-ANVIL-00012 — K&R old-style function definitions fail to parse

- **State:** Draft
- **Priority:** Should
- **Area:** Parser — C language
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Detect an identifier-only parameter list as a K&R definition: parse the bare identifier list, parse the intervening declaration list before `{`, bind each declared type to the matching parameter (default-int for any undeclared), apply standard array/function→pointer parameter decay, and build the typed param list from the result.

## Rationale
The function-definition path unconditionally drives `param_list` → `decl_specifiers`, which rejects an identifier-only parameter; there is no branch to detect a K&R definition, parse the intervening declaration list before `{`, or default-int undeclared params.

- **Current:** A K&R definition (`f(a,b) int a; char b; { ... }`) is rejected with "expected a type" on the first identifier-only parameter; the whole TU fails to compile.
- **Expected (BCC 4.52):** bcc32 accepts K&R definitions — the parenthesised list is identifiers only, parameter types come from the declaration list before the brace (defaulting to `int` where omitted), with array/function parameter decay applied.
- **Blocks:** Compiling the BC4.52 RTL C source (S5) without preprocessing K&R away; any real-world C TU using old-style definitions.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSC-03** — severity medium, type missing-feature, effort M, status new.

- **Evidence:** `src/parser.rs:6189-6243`; `src/parser.rs:6576`, `6607`; error at `src/parser.rs:1397`; oracle `wrk_oracle/bc452/BC45/SOURCE/RTL/SOURCE/IO/COMMON16/SOPEN.C:44-49`.
- **Proposed acceptance oracle (set at Gate 1):** A test parses SOPEN.C's `int sopen(pathP,oflag,shflag,mode) const char *pathP; int oflag; int shflag; unsigned mode; { ... }` and asserts the params are typed `[const char*, int, int, unsigned]`, including a default-int case for an undeclared parameter.
