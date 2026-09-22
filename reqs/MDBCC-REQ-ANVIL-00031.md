# MDBCC-REQ-ANVIL-00031 — Aggregate-by-value ABI override ignores non-trivial destructor / copy-assignment

- **State:** Draft
- **Priority:** Should
- **Area:** Code generation — Win64
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Extend `effective_struct_abi` to classify a size-1/2/4/8 record as `HiddenPtr` when it is non-trivially-copyable: user/non-trivial copy ctor (already covered) OR a declared destructor (`{tag}::~{tag}` present) OR a declared copy-assignment operator (`{tag}::operator =`).

## Rationale
`effective_struct_abi` overrides a size-≤8 record to `HiddenPtr` only when a copy ctor symbol exists; a class with a non-trivial destructor or copy-assignment operator (but an implicit copy ctor) is misclassified `InReg` and packed into a GPR. A user dtor never synthesises an implicit copy-ctor symbol, so the gap is not masked.

- **Current:** Passing/returning a size-≤8 class with a non-trivial destructor (or copy-assignment) by value packs it into a register copy. The callee mutates a register-resident value with no stable `this`, and the caller's temporary destructor runs against an object the callee never wrote back — a use-after-free / double-free or lost mutation for a resource-managing class.
- **Expected (BCC 4.52):** The Microsoft x64 ABI passes and returns any aggregate that is NOT trivially copyable (non-trivial copy ctor, copy-assignment, or destructor) by hidden pointer to a caller-allocated copy, regardless of 1/2/4/8 size. This is the correct oracle because the Win64 ABI is mdbcc's own extension validated against MSVC-built system DLLs.
- **Blocks:** Correct by-value passing of small RAII handle classes (common in OWL/BIDS wrappers); currently a silent narrow-path correctness gap.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C64-02** — severity medium, type spec-conformance, effort S, status new.

- **Evidence:** `src/codegen.rs:787` (`effective_struct_abi`) overrides only on `sigs.copy_ctor_symbol(*id).is_some()` at `src/codegen.rs:791`; `src/codegen.rs:9036-9042` (`lower_struct_arg` packs InReg into a GPR); `src/codegen.rs:9267-9308` (`complete_record_return_call` returns in RAX); dtor detectable at `src/codegen.rs:16531` (`{tag}::~{tag}` in `self.sigs.funcs`); InReg defensive `Err` at `src/codegen.rs:9028` also keys on `copy_ctor_symbol` so it does not fire; synthesis path `src/codegen.rs:1831-1839`.
- **Proposed acceptance oracle (set at Gate 1):** A Win64 test passing AND returning by value a `struct{int h;};`-sized class with a non-trivial `~T()` that records destructor calls, asserting exactly one destruction of one object identity (no register-copy double-destroy), plus a copy-assignment-only variant exercising the `operator =` disqualifier; the InReg copy-ctor defensive net at `src/codegen.rs:9028` must not fire.
