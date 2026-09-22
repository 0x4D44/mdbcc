# MDBCC-REQ-ANVIL-00027 — FP arguments through i386 indirect and virtual calls are a clean `CodegenError`

- **State:** Draft
- **Priority:** Should
- **Area:** Code generation — i386
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Implement FP-argument marshalling in `emit_indirect_call_cdecl` AND the i386 virtual-call path, mirroring `marshal_args_cdecl`'s FP branch (float → `cvtsd2ss` + 4-byte `movss` push; double → 8-byte `movsd` push), so both call kinds accept FP args.

## Rationale
Calling a function pointer or a virtual method with a `float`/`double` argument fails to compile, even though the direct-call path fully supports FP args; both indirect and virtual paths bypass the direct FP-marshalling branch.

- **Current:** A callback `void (*cb)(double)` or a virtual method taking `double` invoked via vtable/pointer fails to compile; the byte-identical direct call works.
- **Expected (BCC 4.52):** cdecl pushes FP args identically whether the call is direct, via a pointer, or via a vtable; an indirect/virtual call with a `double` arg compiles and runs.
- **Blocks:** i386 code using FP-taking callbacks/function pointers and OWL/RTL vtable dispatch (S5/S6 generality).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C32-03** — severity medium, type missing-feature, effort S, status new.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:12792-12797` (`emit_indirect_call_cdecl` rejects FP); `C:\language\mdbcc\src\codegen.rs:12716-12718` (scope comment: scalar int/pointer only); `C:\language\mdbcc\src\codegen.rs:8521-8526` (sibling rejection in the i386 virtual-call path); direct path `marshal_args_cdecl` at `C:\language\mdbcc\src\codegen.rs:14795-14825` supports FP args.
- **Proposed acceptance oracle (set at Gate 1):** i386 tests calling `void (*p)(double); p(3.14);`, `double (*g)(double);` via pointer, and an FP-taking virtual method via vtable compile and produce the same stack image as the direct call; no `CodegenError`.
