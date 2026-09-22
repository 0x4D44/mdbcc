# MDBCC-REQ-ANVIL-00030 — Variadic FP args not duplicated into GPR on the indirect call path

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
Add a `variadic: bool` to `Type::Func`, propagate it through the function-pointer type produced for `&printf`-style targets, and make `emit_indirect_call_with_lead` (and the virtual-call path) apply the same FP-into-GPR duplication that `marshal_args` applies via `callee_variadic`.

## Rationale
A call through a function pointer whose target is variadic places an FP vararg in its XMM register only, never the paired GPR, because `Type::Func` carries no `variadic` flag — so the indirect/virtual marshallers cannot know the pointee is variadic. The defect is confined to FP varargs in positional slots 0..3; slots ≥4 already go through the bit-correct 8-byte stack `mov`.

- **Current:** `int (*fp)(const char*, ...) = printf; fp("%g\n", 3.14);` puts the `double` in xmm2 only. The variadic callee's prologue spills RCX/RDX/R8/R9 into home space (`src/codegen.rs:3842-3847`) and `va_arg(ap, double)` reads the GPR home slot, which holds garbage — the FP value is silently lost.
- **Expected (BCC 4.52):** The Microsoft x64 variadic ABI requires each FP argument to a variadic (or unprototyped) call to be passed in BOTH the XMM register and the corresponding integer register, so the callee's home-space spill recovers the value regardless of how `va_arg` requests it; MSVC/bcc32-on-x64 do this for indirect calls too.
- **Blocks:** Any in-scope TU that stores a variadic function (printf/sprintf/format helpers) in a pointer or dispatch table and calls it with an FP argument — narrow in the OWL target, but a silent FP-arg miscompile when hit.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C64-01** — severity medium, type abi, effort M, status new.

- **Evidence:** `src/codegen.rs:12672-12693` (`emit_indirect_call_with_lead` loads FP args XMM-only, no GPR dup); `src/codegen.rs:8387-8408` (virtual-call path, likewise GPR-dup-free); contrast `src/codegen.rs:14976` + `src/codegen.rs:15182-15185` (`marshal_args` direct path applies the dup via `callee_variadic`); `src/ast.rs:80-83` (`Type::Func` stores only `ret` + `params`); `src/parser.rs:4844-4846` (function-pointer types intentionally drop the `...` bit).
- **Proposed acceptance oracle (set at Gate 1):** A Win64 test that takes the address of a variadic function with a `double`/`float` vararg, calls it through the pointer, and asserts the received FP value is correct (differential against a direct call); confirm the GPR-dup bytes appear at the indirect call site.
