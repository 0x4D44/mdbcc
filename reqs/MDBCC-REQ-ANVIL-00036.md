# MDBCC-REQ-ANVIL-00036 — `__stdcall` callee cleanup assumes every parameter is 4 bytes (8-byte and by-value-struct params mis-sized)

- **State:** Draft
- **Priority:** Should
- **Area:** Calling conventions & ABI
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Compute the `__stdcall` callee-clean immediate as the sum of each parameter's actual stack footprint (`size().max(4)` rounded up to 4), or extend the existing scope gate to also reject `__stdcall` with any >4-byte scalar or by-value-record parameter with a clean `CodegenError`.

## Rationale
The callee-clean immediate is computed as `4 * f.params.len()`, but the preceding gates reject struct-by-value return, any float param, and implicit `this` — not a `long long`/`__int64` (8 bytes, not caught by `is_float`) nor a by-value record param (full size pushed).

- **Current:** `void __stdcall f(long long x)` pushes 8 bytes for `x` but the callee emits `ret 4`, leaving esp 4 bytes low on return — a silent stack imbalance. A by-value struct param (size ≠ 4) is likewise mis-counted.
- **Expected (BCC 4.52):** The `__stdcall` callee cleans exactly the total pushed argument-area size: the sum of each arg's stack footprint (8 for `long long`/`double`, struct-size rounded up for by-value records), not `4 * count`.
- **Blocks:** Correct `__stdcall` ABI for 64-bit or aggregate parameters; low immediate blast radius (WINAPI callbacks are overwhelmingly 4-byte scalar/pointer args) but a latent corruptor.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **ABI-05** — severity medium, type bug, effort S, status new.

- **Evidence:** `src/codegen.rs:3108` (`4usize * f.params.len()`); gates at `src/codegen.rs:3087`, `:3094`, `:3101`; caller skips its own cleanup for stdcall at `:14598`; long-long push at `:14838`; by-value-record push at `:14788`.
- **Proposed acceptance oracle (set at Gate 1):** `int __stdcall f(long long x){return (int)x;}` either returns the correct `ret 8` (a single 8-byte arg) verified by an i386 byte/run test, or is rejected with a `CodegenError`; esp is balanced after the call.
