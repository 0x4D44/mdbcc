# MDBCC-REQ-ANVIL-00033 — Calling convention is absent from `Type::Func`; indirect calls cannot honor a non-cdecl callee

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
Carry the calling convention on the function-pointer type (add an `Option<CallConv>` to `Type::Func`, threaded by the parser) and have the i386 indirect-call path skip caller cleanup when the pointed-to convention is callee-clean (stdcall/fastcall/pascal); until then, reject an indirect call through a non-cdecl function pointer with a clean `CodegenError`.

## Rationale
`Type::Func { ret, params }` carries no convention field, so the i386 indirect-call path unconditionally reclaims pushed bytes caller-side and recovers only `params`; the convention is unavailable at the call site, and the direct-call `Stdcall` skip keys on the callee name (which an indirect call cannot supply).

- **Current:** An indirect call through a `void (__stdcall *p)(int,int)` pushes the args and then emits `add esp,8` caller-side while the stdcall callee also did `ret 8` (`RetImm` at `src/codegen.rs:4481`/`4498`) — esp is corrected twice, corrupting the stack. No guard rejects a non-cdecl indirect call, so it is not even a clean error.
- **Expected (BCC 4.52):** The convention encoded in the function-pointer type is honored at the indirect call site: a `__stdcall` fn-ptr call performs no caller cleanup; a `__cdecl` fn-ptr call cleans caller-side.
- **Blocks:** Any i386 source that stores a stdcall callback (WNDPROC/DLGPROC) and invokes it indirectly from mdbcc-emitted code; correct fn-pointer ABI typing generally. (The headline OWL callbacks are invoked by Windows, not indirectly from emitted code, narrowing the live trigger.)

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **ABI-02** — severity high, type bug, effort L, status new.

- **Evidence:** `src/ast.rs:80`–`83`; `emit_indirect_call_cdecl` cleanup at `src/codegen.rs:12856`–`12862` (doc comment `src/codegen.rs:12713`–`12714`), params recovery at `src/codegen.rs:12736`–`12740`; name-keyed skip at `src/codegen.rs:14595`. Parser's `skip_call_conv` records into `last_call_conv` but it is dropped for function-pointer types.
- **Proposed acceptance oracle (set at Gate 1):** A test storing a `__stdcall` function's address in a typed pointer and calling through it either runs with a balanced stack (verified by an i386 run test returning a sentinel after the call) or yields a `CodegenError`. No path double-cleans the stack.
