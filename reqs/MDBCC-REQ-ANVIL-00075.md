# MDBCC-REQ-ANVIL-00075 — Most codegen errors carry no source location

- **State:** Draft
- **Priority:** Should
- **Area:** Diagnostics
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Every `CodegenError` reaching the user must carry a source location (line/col); add a `Loc` to `CodegenError` or route all user-reachable sites through `err_at_loc`/`err_here`, making synthetic/parser-injected and `pe_writer` locations the rare exception.

## Rationale
`CodegenError` is a bare `String` with no `Loc` field, so the long tail of emission sites reports errors with no line or column. The most common user-facing classes are already located via `err_at_loc`/`err_here`, but the breadth across rarer sites is missing.

- **Current:** Most codegen errors render as `foo.cpp:error: <message>` with no line or column, forcing the user to grep the source for the offending construct.
- **Expected (BCC 4.52):** bcc32 prefixes every compiler diagnostic with file and line, e.g. `Error E2451 FOO.CPP 12: Undefined symbol 'x' in function main()`; every user-reachable error must pinpoint a source line.
- **Blocks:** Diagnosing the scratchpad OWL sample failures (GROUPBOX/EDIT/HELLOAPP) on the S6 path; any user-facing compile-error UX.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DIAG-01** — severity medium, type diagnostics, effort L, status sharpens-parked.

- **Evidence:** `src/codegen.rs:61` (`pub struct CodegenError(pub String);`), Display at `src/codegen.rs:65` (`error: {}`); located path at `src/codegen.rs:3426` (`err_at_loc`) / `src/codegen.rs:3431` (`format!("{}:{}: {}", loc.line, loc.col, msg)`); driver render at `src/main.rs:217,259` (`{path}:{e}`). Roughly 90–99 raw `Err(CodegenError(` sites vs ~33–35 located sites (the higher raw count includes ~9 `src/link/pe_writer.rs` PE/linker-internal sites that legitimately have no source loc). Unlocated high-value sites: unknown struct type `src/codegen.rs:7064`, no-matching-overload `src/codegen.rs:8116`.
- **Proposed acceptance oracle (set at Gate 1):** A test compiling a TU that triggers each major codegen-error class (unknown type, unresolved overload, unsupported `new` form) asserts the emitted message begins with `<line>:<col>:`; the count of raw `Err(CodegenError(` sites lacking a location drops to near-zero (synthetic nodes and `pe_writer` excepted).
