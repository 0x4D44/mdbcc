# MDBCC-REQ-ANVIL-00039 — Exception specifications (`throw()`/`throw(T)`) are parsed and discarded with no enforcement

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
Carry the exception-specification type list onto the function AST and, at minimum for the empty `throw()` spec, wrap the body so an escaping exception routes to `terminate()` — matching Borland semantics; full `throw(T)` type-filtering is the broader follow-on.

## Rationale
`throw(...)` specs are consumed and thrown away — no `ExceptionSpec` node reaches the AST and no enforcement exists, so a throw escaping a `throw()` function never reaches `terminate()` and a disallowed type never reaches `unexpected()`.

- **Current:** A function declared `void f() throw()` or `void g() throw(xmsg)` that throws a disallowed type propagates the exception normally; the violation is never detected and `std::unexpected`/`terminate` is never called.
- **Expected (BCC 4.52):** BCC 4.52 enforces dynamic exception specifications: a throw escaping a `throw()` function calls `terminate()`; a throw of a type not in `throw(T)` calls `unexpected()` (default `terminate`). `EXCEPT.H` declares these throughout the RTL (`void raise() throw(xmsg)`), and the empty `throw()` spec is pervasive in in-scope headers (`CSTRING.H` ×27, OWL `WINDOW.H`/`APPLICAT.H`).
- **Blocks:** Error-path/`terminate` parity with the RTL/`EXCEPT.H` (happy-path parity does not require this); none for normal execution.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **EH-03** — severity medium, type missing-feature, effort M, status new.

- **Evidence:** `src/parser.rs:6669-6683` (`skip_exception_spec` discards the type list; doc at `6664-6668` marks it "deferred HLD S4"), called from ~9 sites (`2305`, `2358`, `2420`, `2614`, `6194`, `6444`, `6519`); no `ThrowSpec`/exception-specification node appears in codegen.
- **Proposed acceptance oracle (set at Gate 1):** A test where `void f() throw() { throw 1; }` called under a `try`/`catch` in `main()` does NOT reach the catch but instead terminates (observable as the terminate/abort exit path), distinct from current behaviour where the catch fires. Env-skip the differential vs `bcc32` if `BIN/` is absent.
