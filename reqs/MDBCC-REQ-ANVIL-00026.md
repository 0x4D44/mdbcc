# MDBCC-REQ-ANVIL-00026 — i386 64-bit division and modulo emit a clean `CodegenError`

- **State:** Draft
- **Priority:** Must
- **Area:** Code generation — i386
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Lower i386 `long long`/`unsigned long long` `/` and `%` to a software 64/64 divide — emitted inline or a call to a runtime helper symbol — covering signed and unsigned and producing quotient (Div) vs remainder (Mod) in EDX:EAX.

## Rationale
Any 64-bit `/`, `%`, or compound `/=`/`%=` on i386 aborts compilation; no software 64/64 divide exists anywhere in the backend, though all other 64-bit pair ops are implemented.

- **Current:** `long long a / b`, `a % b`, `unsigned long long` divide, or 64-bit `/=`/`%=` aborts with `"i386 long long division/modulo is not supported yet"`.
- **Expected (BCC 4.52):** i386 lowers 64-bit `/` and `%` to RTL helpers (the `__lldiv`/`__lludiv` 8-byte `__int64` family), so the expression compiles and runs.
- **Blocks:** Any in-scope i386 source doing 64-bit division (timestamps, file sizes, fixed-point); full S2 integer completeness.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C32-02** — severity high, type missing-feature, effort M, status sharpens-parked.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:11403-11407` (binary-op dispatch returns the error); `C:\language\mdbcc\src\codegen.rs:11742-11746` (same guard in `gen_intop_i386_i64`); other 64-bit pair ops implemented at `C:\language\mdbcc\src\codegen.rs:11722-11769`.
- **Proposed acceptance oracle (set at Gate 1):** `tests/i386_run.rs` cases for signed/unsigned 64-bit `/` and `%` (incl. negative operands and divide-by-large-value) match the Win64 path / a reference; no `CodegenError`.
