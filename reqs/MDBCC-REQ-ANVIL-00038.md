# MDBCC-REQ-ANVIL-00038 — i386/Win32 has no partial-construction or array-new cleanup pads and no catch-side exception-object destruction

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
Port the Win64 Cleanup-scope machinery (ctor partial-construction counter+pad, array-new live-iter pad, catch-ref dtor registration) to the i386 `fs:[0]` SEH3 path, or document each as a permanent i386 residual with a clean diagnostic where a leak would otherwise be silent.

## Rationale
The entire Win64 Cleanup machinery (ctor partial-construction counter+pad, array-new live-iter pad, catch-ref dtor) is gated Win64-only, so on i386 none of it runs: mid-ctor throws leak base/member subobjects, mid-array-new throws leak constructed elements and the `HeapAlloc` block, and caught `catch(T&)` objects are never destroyed at handler exit.

- **Current:** On i386: (a) a ctor body that throws after constructing a base/member leaves those subobjects undestroyed; (b) `new T[N]` that throws mid-loop leaks the constructed elements and the heap block; (c) a caught `catch(T& e)` object is never destroyed at handler completion. All three are correct on Win64.
- **Expected (BCC 4.52):** BCC 4.52 32-bit (`bcc32` + `TLINK32`) runs base/member dtors on a mid-ctor throw, destroys `[0..K-1]` and frees the block on a mid-array-new throw, and destroys the caught exception object at handler exit — identically to its 64-bit-era equivalent.
- **Blocks:** i386 OWL/RTL exception correctness (S6 32-bit OWL samples); the parked "i386 partial-construction EH cleanup" item (`BUGS.md:37-40`).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **EH-02** — severity high, type incomplete, effort XL, status sharpens-parked.

- **Evidence:** `src/codegen.rs:4003-4004` (`cleanup_enabled = … && self.target != TargetKind::Win32`); `src/codegen.rs:4040-4041` (member-counter slot also `!= Win32`); `src/codegen.rs:4878-4880` (`track_catch_ref_dtor` early-returns unless Win64); i386 array-new sidestep documented at `src/codegen.rs:4034-4039` and `16544-16567`, dispatched to `gen_new_array_i386` at `src/codegen.rs:16625` with no pad (comment at `16621-16624`).
- **Proposed acceptance oracle (set at Gate 1):** `tests/i386_run.rs` gains twins of `t45`/`t47`/`t49` (ctor base+member cleanup), the array-new partial-construction case, and a catch-ref-dtor case; each asserts the dtor side effect fired. i386 byte-identity baselines re-blessed where pad bytes are added.
