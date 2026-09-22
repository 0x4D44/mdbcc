# MDBCC-REQ-ANVIL-00108 — Static/global object destructors are never run at program exit (no `.mdbcc_dtor`/atexit path)

- **State:** Draft
- **Priority:** Must
- **Area:** Cross-seam / completeness
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Emit a symmetric `.mdbcc_dtor.*` (or atexit-registration) path so file-scope/function-static objects with non-trivial destructors are destroyed in reverse construction order at normal program exit, for both `main` and `WinMain`/`OwlMain` entry shapes.

## Rationale
File-scope and function-`static` objects with non-trivial destructors are constructed but never destroyed when the program exits. No dimension owns program-shutdown destruction: EH-01/EH-02/EH-05 cover destruction on the *exceptional* path; the static-init dimension covers only construction.

- **Current:** `.mdbcc_ctor.*` thunks run before main/WinMain; nothing runs on exit. A global `ofstream`/`strstream`/`string`/`TString` never flushes or frees on shutdown.
- **Expected (BCC 4.52):** bcc32 registers static-object destructors (via `atexit`/the `__cdtors` exit list) so they run LIFO at `exit()`, flushing buffered streams and releasing resources.
- **Blocks:** S5/S6 — OWL/RTL global objects (diagnostic streams, locale tables) leak or fail to flush on exit, diverging from the bcc32 reference.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **GAP-01** — severity high, type missing-feature, effort L, status open.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:1004` builds `static_init_stmts` / `ctor_thunk_specs` (construction only); `C:\language\mdbcc\src\codegen.rs:1299-1311` queue ctor statements with no symmetric dtor queue. A grep for `mdbcc_dtor`/`collect_dtor`/`atexit` across `src/` and `src/link/` finds zero implementations; `C:\language\mdbcc\src\link\crt.rs:48-51` explicitly defers it ("If S8 adds argv parsing or atexit registration, that's the moment to add an `.xdata` entry").
- **Proposed acceptance oracle (set at Gate 1):** A program with a file-scope object whose destructor has an observable side effect (writes a sentinel / flushes a buffer) shows that side effect on clean exit; ordering is reverse-of-construction across a multi-TU link.
