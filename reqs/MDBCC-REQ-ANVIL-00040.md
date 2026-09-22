# MDBCC-REQ-ANVIL-00040 — A dtor that throws while an exception is already in flight does not call `terminate` (J-12b)

- **State:** Draft
- **Priority:** Should
- **Area:** Exception handling
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Detect a throw raised while an unwind is in progress — an in-flight-exception flag set by the personality before `RtlUnwindEx`/`RtlUnwind` and cleared at handler entry — and route it to `terminate()` instead of re-dispatching.

## Rationale
There is no in-flight-exception flag, so a throw raised by a destructor during unwinding is dispatched as an independent fresh exception (non-deterministically caught by an unrelated outer handler or AV) rather than routed to `terminate()` per the double-throw rule.

- **Current:** A destructor that throws during unwinding produces a non-deterministic outcome (caught by an unrelated outer handler or an uncontrolled `STATUS_*` kill) rather than a defined `std::terminate`; because the single `.mdbcc_eh_buffer` is shared, a second class throw can clobber the first exception's object mid-unwind.
- **Expected (BCC 4.52):** BCC 4.52 calls `terminate()` when a second exception is raised during stack unwinding of the first (the classic double-throw rule).
- **Blocks:** Defined behaviour on the double-throw path; safe interaction with EH-01 (once locals are destroyed during unwind, throwing dtors become reachable).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **EH-04** — severity medium, type incomplete, effort M, status sharpens-parked.

- **Evidence:** `tests/cpp_exceptions.rs:1662-1666` (documents the J-12b deferral; a mid-unwind dtor throw "will surface as a `STATUS_*` process kill"); no in-flight flag in `eh.rs`; single shared `.mdbcc_eh_buffer` noted at `src/codegen.rs:278-281`; all SEH personalities `ContinueSearch` during `EH_UNWINDING` (no nested-throw guard).
- **Proposed acceptance oracle (set at Gate 1):** A test where an object with `~T(){ throw 2; }` is a local destroyed while exception 1 unwinds; assert the process takes the `terminate` path deterministically (not an arbitrary AV or unrelated catch), distinct from the single-throw `t44` case which must still be caught.
