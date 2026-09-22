# MDBCC-REQ-ANVIL-00037 — Function-scope locals are not destroyed when an exception propagates through a frame (both targets)

- **State:** Draft
- **Priority:** Must
- **Area:** Exception handling
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Register a Cleanup landing pad (or equivalent unwind funclet) for every function frame that owns automatic objects with destructors, so the OS unwind invokes the reverse-order dtor chain for that frame when an exception propagates through it — not only for ctor bodies and array-new loops.

## Rationale
A plain function frame holding a fully-constructed automatic object `T local;` (non-trivial dtor) with no enclosing `try` registers no Cleanup TryScope on either target, so when an exception merely propagates through that frame the OS unwinder finds no handler and the local's destructor never runs.

- **Current:** When an exception unwinds through a function whose body has automatic objects with non-trivial destructors but no enclosing `try`, those destructors are never called. The catch fires correctly (control flow is right) but every stack object between the throw site and the catch leaks its owned resources.
- **Expected (BCC 4.52):** BCC 4.52 (and ISO C++) destroy every fully-constructed automatic object in each frame as the exception unwinds through it, in reverse construction order. OWL/RTL throw paths are saturated with such locals (e.g. a `string`/`TStringRef` owning heap, ios sentry guards), so a single thrown `xmsg` leaks heap across every intermediate frame.
- **Blocks:** Leak-free OWL/RTL exception paths; the `STATICX.CPP`-class heap-corruption (`0xC0000374`) and scratchpad `HELLOAPP`/`POPUP` product-mode crashes plausibly (unproven) share this root cause.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **EH-01** — severity high, type bug, effort L, status new.

- **Evidence:** `src/codegen.rs:4845-4848` (design comment: dtors emitted as pure fall-through code, not unwind funclets); the only two `CatchPolicy::Cleanup` registrations are `src/codegen.rs:4241` (ctor partial-construction) and `src/codegen.rs:16972` (array-new); `emit_all_dtors` at `src/codegen.rs:4966` is invoked only from `Stmt::Return` and structured normal-exit paths (`5170`, `5210`, `5238-5252`), never as an unwind landing pad; `tests/cpp_exceptions.rs:1323` (same fall-through design note).
- **Proposed acceptance oracle (set at Gate 1):** A test where `f()` holds `Guard g;` (whose dtor sets a global flag / decrements a refcount), calls a function that throws, and the throw is caught in `main()`; assert the flag/refcount proves `g` was destroyed during unwind. Must pass on Win64 (i386 twin is the follow-on). Run against the existing `run_src` harness in `tests/cpp_exceptions.rs`.
