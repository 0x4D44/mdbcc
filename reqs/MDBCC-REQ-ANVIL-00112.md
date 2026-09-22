# MDBCC-REQ-ANVIL-00112 — `abort()`/`exit()` mid-program do not run the registered ctor/exit/dtor wind-down

- **State:** Draft
- **Priority:** Should
- **Area:** Cross-seam / completeness
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Once GAP-01/GAP-04 exist, route the RTL `exit()` through the same wind-down chain so an explicit exit triggers destructors and exit handlers; keep `abort()` as a direct terminate.

## Rationale
Because there is no atexit/exit-handler registry at all (GAP-01/GAP-04), an explicit `exit(n)` from user/OWL code cannot run static destructors or `#pragma exit` handlers; it can only fall through to the OS `ExitProcess`. This is a distinct *entry point into shutdown* not captured by the throw-path EH items.

- **Current:** `exit(0)` terminates without flushing global streams or invoking exit handlers; behavior diverges from bcc32 whenever a global object's dtor or a `#pragma exit` handler has observable effects.
- **Expected (BCC 4.52):** `exit()` runs the C `atexit` chain and static destructors before terminating; `abort()` bypasses them (matching the C/C++ contract).
- **Blocks:** S6 — OWL sample apps that close via `exit()`/menu-quit paths.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **GAP-05** — severity medium, type incomplete, effort M, status open.

- **Evidence:** No exit-handler table exists (`atexit` only appears in a `parser.rs` typedef comment at `C:\language\mdbcc\src\parser.rs:4559` and the deferred crt note); the only shutdown wiring is the `.mdbcc_ctor` thunk run *before* entry (`C:\language\mdbcc\src\link\pe_writer.rs:3238` `collect_ctor_thunks`). There is no `collect_dtor_thunks` counterpart.
- **Proposed acceptance oracle (set at Gate 1):** A program calling `exit(0)` after constructing a global object with an observable dtor shows the dtor side effect; `abort()` does not.
