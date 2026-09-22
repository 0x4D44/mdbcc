# MDBCC-REQ-ANVIL-00082 — No `@response-file` expansion in any driver

- **State:** Draft
- **Priority:** Should
- **Area:** Driver / CLI / project
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Each driver must, before option parsing, expand any argument of the form `@<path>` by reading the file and splicing its whitespace-separated tokens into the argument stream in place (recursively, with documented BC quoting).

## Rationale
None of `bcc`, `mdlink`, `mdar`, `mdrc` expands a leading `@<file>` argument; all four read arguments only from argv, so a literal `@foo` is consumed as a positional input (mdlink/mdar/bcc) or rejected.

- **Current:** A leading `@<path>` is silently treated as an input filename, producing a no-such-file error rather than being expanded.
- **Expected (BCC 4.52):** TLINK32, BRC32, TLIB and BCC32 all expand a leading `@<file>` argument by splicing whitespace/newline-separated tokens from that file into the argument stream before option parsing (the `@&&|...|` inline form is make emitting a temp response file then passing `@tempfile`); stock makefiles depend on it to avoid Windows command-line overflow.
- **Blocks:** Driving the tools with unmodified BC4.52 MAKEFILE.GEN link/lib rules and direct reuse of stock TLINK32/TLIB response files (optional, off the native build path).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-02** — severity medium, type missing-feature, effort M, status new.

- **Evidence:** `src/bin/mdlink.rs:201-293` (any non-flag arg becomes a positional `.obj` path, unknown `-`/`/` flags rejected, no `@` handling); `src/main.rs:55-104`, `src/bin/mdrc.rs:77-128`, `src/bin/mdar.rs:23-36` likewise have no `@file` branch; grep for `response|@file|read_response` across `src/` yields only doc-comments; oracle `EXAMPLES/MAKEFILE.GEN:615-722` links every EXE/DLL with `$(TLINK) @&&|...|` and the RC step with `$(RLINK) @&&|`.
- **Proposed acceptance oracle (set at Gate 1):** A response file containing object paths, output and flags drives `mdlink @resp.txt` to a PE matching the equivalent explicit-argv link; same for `mdar` (`+obj` member list) and `bcc`.
