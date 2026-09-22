# MDBCC-REQ-ANVIL-00041 — Throw-operand temporary (`throw E(x)`) is never destroyed

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
After `emit_throw_object_copy` materializes the EH buffer, emit the throw-operand temporary's destructor — only when the operand is a materialized temporary (a constructor-call rvalue) with a dtor, and never for `throw existing_lvalue;` — before `RaiseException`, on both targets.

## Rationale
`throw E(x)` deep-copies the operand into the EH buffer and raises, but the source temporary's destructor is never emitted on the (non-returning) throw path, leaking one allocation per throw for a heap-owning class.

- **Current:** `throw E(x)` constructs a temporary `E`, deep-copies it into the EH buffer, and raises — but the source temporary's destructor never runs, leaking its owned resource. (Post-B-08 the buffer copy is deep, so this is a pure resource/refcount leak, not aliasing/use-after-free.)
- **Expected (BCC 4.52):** BCC 4.52 destroys the throw-operand temporary after the exception object has been copy-constructed into EH storage (the temporary's lifetime ends at the throw, after the copy).
- **Blocks:** Leak-free `throw E(args)` (the common throw form); complete exception-object lifetime symmetry.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **EH-05** — severity medium, type incomplete, effort M, status new.

- **Evidence:** `src/codegen.rs:6315` (`gen_throw_class` evaluates the operand), `6406` (`emit_throw_object_copy` deep-copies into `.mdbcc_eh_buffer`), `6461` (`RaiseException`) with a `ud2` fall-through at `6464`; the B-08 HLD (`wrk_docs/2026.06.16 - HLD - B-08 …md` §2) lists "Throw-operand temporary destruction" as a separate pre-existing gap, not B-08.
- **Proposed acceptance oracle (set at Gate 1):** A test where `E`'s ctor and dtor each tick a counter and `throw E(7)` is caught; assert the temporary's dtor ran exactly once (counter balanced) in addition to the caught copy's dtor.
