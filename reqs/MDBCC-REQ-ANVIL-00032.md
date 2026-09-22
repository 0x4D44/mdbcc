# MDBCC-REQ-ANVIL-00032 — `__fastcall`/`__pascal` are parsed but never consumed and silently emit cdecl

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
Either implement i386 `__fastcall` (ECX/EDX register args + callee-clean + `@name` decoration) and `__pascal` (left-to-right push + callee-clean), or — at minimum, immediately — reject any function definition or call whose effective convention is `Fastcall`/`Pascal` on i386 with a clean `CodegenError`, mirroring the existing `Stdcall` scope gates, so no source is ever silently miscompiled.

## Rationale
The parser records `CallConv::Fastcall`/`Pascal` and codegen copies them into `sigs.convs`, but codegen reads only the two `Stdcall` checks; no site reads `Fastcall`/`Pascal`, so such functions fall through every gate and are emitted/called exactly as cdecl, with the deferral acknowledged in a comment only and no clean-error guard.

- **Current:** `int __fastcall f(int a,int b)` is compiled with both args on the stack and caller-clean cleanup (cdecl); `__pascal` likewise emits cdecl bytes. No diagnostic is produced; the only "coverage" is a parse-smoke tripwire that the test file itself documents does not prove support, and the GUI `PASCAL`/`WINAPI` macros expand away.
- **Expected (BCC 4.52):** Borland `__fastcall` passes leading ≤32-bit integer/pointer args in ECX then EDX (remainder on the stack right-to-left), is callee-clean, and decorates names as `@name`; `__pascal` pushes parameters left-to-right and the callee cleans. The CD source uses `_fastcall` for the vector-new/delete dtor-loop callback (`RTL/SOURCE/MEMORY/COMMON32/VNEW.CPP:21`) and `__pascal` in `BCD.H:143`–`146`,`386`–`387`.
- **Blocks:** Compiling any in-scope TU that genuinely uses `__fastcall`/`__pascal` (RTL MEMORY vector helpers, `BCD.H` operators). The clean-error gate is the S-effort floor.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **ABI-01** — severity critical, type bug, effort L, status sharpens-parked.

- **Evidence:** `src/parser.rs:1271`–`1275`, `src/parser.rs:4329`–`4333`; `src/codegen.rs:903`–`908`; reads at `src/codegen.rs:3086` and `src/codegen.rs:14595`; deferral comment at `src/codegen.rs:3084`.
- **Proposed acceptance oracle (set at Gate 1):** A test compiling `int __fastcall f(int a,int b){return a-b;}` plus a caller either (a) produces correct ECX/EDX-in, callee-clean bytes verified by an i386 run test, or (b) returns a `CodegenError` naming the unsupported convention. No path emits cdecl bytes for a `__fastcall`/`__pascal` function silently.
