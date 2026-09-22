# MDBCC-REQ-ANVIL-00109 — Class temporaries are never destroyed at end of the full-expression on the normal path

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
Track temporaries materialized within a full-expression and emit their destructor calls at the statement boundary on the normal-exit path.

## Rationale
A materialized class temporary (function/operator returning a record by value, an implicit conversion temporary) is never destructed at the end of the enclosing full-expression. EH-05 captures only the *throw-operand* temporary; the ordinary `cout << string("a")+string("b");` case is uncaptured.

- **Current:** Temporaries holding heap allocations (string/TString/strstream) leak once per evaluation; for an object whose dtor flushes, the side effect is dropped.
- **Expected (BCC 4.52):** Each full-expression's materialized temporaries are destroyed in reverse order of construction at the statement's end (C++ temporary lifetime), as bcc32 does.
- **Blocks:** S5/S6 — OWL/BIDS string and stream temporaries leak; long-running sample apps accrete memory and may diverge from the reference.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **GAP-02** — severity high, type incomplete, effort L, status open.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:9184-9190` allocates a result buffer for a record-returning operator but no end-of-statement destructor is run on it. Grep for `temp.*dtor`/`destroy.*temporary`/`pending_dtor`/`full.expression` in `codegen.rs` finds no temporary-cleanup machinery (only the throw-path cleanups).
- **Proposed acceptance oracle (set at Gate 1):** `string s = string("a") + string("b");` and `f(string("x"))` (with an observable-side-effect dtor / leak check) destroy exactly the right temporaries once each; no leak across a loop iterating such expressions.
