# MDBCC-REQ-ANVIL-00035 — Member-function-pointer dispatch is single-inheritance-only: no `this`-delta for secondary-base methods

- **State:** Draft
- **Priority:** Must
- **Area:** Calling conventions & ABI
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Either encode the `this`-delta in the MFP value (or a side table) and apply it at the `.* / ->*` call site for multiple-inheritance/secondary-base targets, or detect a secondary-base/`this`-shifting MFP target (offset != 0) and reject it with a clean `CodegenError` instead of dispatching with an unadjusted `this`.

## Rationale
The MFP value is an 8-byte code-address / vtable-slot encoding with no `this`-adjustment delta and no side table; the resolver explicitly assumes single inheritance keeps slot indices stable. `this_adjust` exists only on `VtableImage` for RTTI/`dynamic_cast`, not for MFP `this` fixups.

- **Current:** `&Derived::m` where non-virtual `m` is inherited from a secondary (non-primary) base, invoked through a member-function pointer, resolves to the correct symbol but passes the complete-object `this = &recv` verbatim; the callee then dereferences the wrong subobject (the secondary base lives at `+base_offset`). Single-inheritance and primary-base MFP, and virtual secondary-base targets routed through `this`-adjusting thunks, are correct.
- **Expected (BCC 4.52):** Member-function pointers carry the `this`-adjustment so a call through a pmf to a method of a secondary base adjusts `this` by the base offset before dispatch; the OWL GENERIC response-table dispatcher (`DISPATCH.CPP`, `(generic.*pmf)(...)`) must deliver the correct subobject pointer.
- **Blocks:** OWL response-table handlers (`DISPATCH.CPP`) whose event method is inherited via a secondary/mixed-in base; multiple-inheritance MFP correctness generally. The minimal-correct first step is a clean `CodegenError` reject of a non-virtual secondary-base MFP target.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **ABI-04** — severity high, type incomplete, effort L, status new.

- **Evidence:** MFP encoding at `src/codegen.rs:13185`–`13186`; single-inheritance assumption comment at `src/codegen.rs:13207`–`13211`; `this_adjust` at `src/codegen.rs:217` (used at `:2540`,`:2570`); call path `gen_member_ptr_call` at `src/codegen.rs:13306`; virtual secondary-base thunks at `src/codegen.rs:2578`–`2579`.
- **Proposed acceptance oracle (set at Gate 1):** A test forms `&Derived::m` for `m` from a second base, calls it through a pmf on a `Derived` object, and observes the method seeing the correct base subobject (a field-value oracle); or the construction is cleanly rejected.
