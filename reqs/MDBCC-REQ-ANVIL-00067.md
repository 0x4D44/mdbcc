# MDBCC-REQ-ANVIL-00067 — Member-function-pointer value carries no this-adjustment; OWL response-table dispatch on virtual/non-leftmost bases passes the wrong `this`

- **State:** Draft
- **Priority:** Must
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
The member-function-pointer representation and `.*`/`->*` lowering must apply the correct this-pointer adjustment for targets in non-zero-offset and virtual-base subobjects, so a reinterpret-cast generic PMF call enters the handler with a correctly-adjusted `this` on both Win64 and i386.

## Rationale
`Type::MemFn` is a bare 8-byte value (code address, or a bit-63-tagged vtable offset) with no adjustor/delta or vindex field, and `.*`/`->*` lowering applies only the virtual-slot vtable indirection — never a base-subobject this-delta. A reinterpret-cast generic PMF (OWL's response-table dispatch) therefore enters a handler inherited from a virtual or non-leftmost base with `this` pointing at the most-derived object instead of the correct subobject.

- **Current:** A PMF to a method of a virtual base (or non-leftmost base) is dispatched with `this` unadjusted. It works only when the relevant subobject sits at offset 0 of the receiver (true for BUTTON/INSTANCE), silently delivering a misaligned `this` otherwise.
- **Expected (BCC 4.52):** bcc32 member-function pointers carry the this-adjustment (and vindex) so that a generic-PMF call lands the handler with `this` adjusted to the correct subobject regardless of where `TWindow`/`TEventHandler` sit in the most-derived layout; OWL's crack-and-dispatch design depends on this.
- **Blocks:** General OWL message dispatch for any control/window whose handlers are not at offset 0; plausible root of the STATICX heap corruption and HELLO/POPUP crashes. Blocks S6/S7 generality.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-01** — severity critical, type bug, effort L, status new.

- **Evidence:** `src/ast.rs:84-94` (MemFn representation, no delta); `src/codegen.rs:13362-13391` (i386 `.*`/`->*`), `src/codegen.rs:13452-13514` (Win64), `src/codegen.rs:13187-13258` (`resolve_member_for_mfp_target` discards which subobject the method lives in); OWL dispatch in `INCLUDE/owl/EVENTHAN.H:97-108` (PMF cast to `TGenericTableEntry`), `INCLUDE/owl/DISPATCH.H:28,40` (`TAnyPMF`/`TAnyDispatcher`), `WINDOW.CPP:854-857`; virtual-inheritance hierarchy in `window.h:152-153`, `framewin.h:63`.
- **Proposed acceptance oracle (set at Gate 1):** A test that takes `&Derived::baseMethod` (base at a non-zero / virtual-base offset), stores it in a `TAnyPMF`-shaped slot, calls it through a differently-typed PMF, and asserts the callee observes the correct `this` (e.g. reads a base field set to a sentinel); plus an OWL sample whose handler lives in a non-leftmost subobject (a multi-base control) that builds and dispatches a message correctly.
