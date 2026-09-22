# MDBCC-REQ-ANVIL-00080 — Diagnostic format diverges from bcc32 (line:col, no error number or caret)

- **State:** Draft
- **Priority:** Could
- **Area:** Diagnostics
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
If byte/format parity with bcc32 reference output is a gate, render the bcc32 message shape (file + line + numbered code); otherwise record the deliberate gcc-style divergence (e.g. in BUGS.md/wrk_docs) so it isn't mistaken for a defect. The cheaper correct resolution is the documented decision.

## Rationale
All compiler channels emit gcc/clang-style `{path}:{line}:{col}: error: {msg}` rather than the bcc32 `Error E<nnnn> <FILE> <line>:` shape, with no numbered code and no caret/source-snippet rendering. The divergence is neither documented as deliberate nor pinned by a formatter test.

- **Current:** Output reads `foo.cpp:12:5: error: Undefined symbol 'x'` (gcc/clang-style line:col, no number, no caret).
- **Expected (BCC 4.52):** `Error E2451 FOO.CPP 12: Undefined symbol 'x' in function main()` — error number, uppercase filename in the body, line only, no column.
- **Blocks:** Any future differential test that compares mdbcc stderr against captured bcc32 stderr (no current gate; oracle/differential tests compare object/PE bytes and runtime behaviour).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DIAG-06** — severity low, type spec-conformance, effort M, status confirmed.

- **Evidence:** Formatting at `src/lexer.rs:239`, `src/pp.rs:28`, `src/parser.rs:23`, `src/codegen.rs:3431`; filename prepended by the driver at `src/main.rs:144,189,217,259`; no caret rendering (the only `^` hits are the XOR token at `src/parser.rs:4200`, `src/pp.rs:1889`).
- **Proposed acceptance oracle (set at Gate 1):** Either a documented decision in BUGS.md/wrk_docs that mdbcc uses gcc-style diagnostics by design, or a formatter test asserting the bcc32 `Error E<nnnn> <FILE> <line>:` shape.
