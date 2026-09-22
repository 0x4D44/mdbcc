# MDBCC-REQ-ANVIL-00063 — printf intrinsic truncates `long long` to its low 32 bits (silent miscompile)

- **State:** Draft
- **Priority:** Should
- **Area:** RTL / CRT / iostreams
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Honor the `l`/`ll`/`L` length modifiers: route `%lld`/`%llx`/`%llu` through a 64-bit format path (EDX:EAX on i386, RAX on Win64) rather than truncating, or emit a clean `CodegenError` for the unsupported width instead of silently truncating.

## Rationale
The `printf` intrinsic consumes and ignores the `l`/`ll`/`L` length modifiers and formats every integer from the low 32 bits, so `%lld`/`%llx`/`%llu` of a 64-bit value prints wrong digits with no error. (The auxiliary claim that `%ld` truncates on Win64 is incorrect — `long` is 4 bytes in this LLP64 model; the bug is purely `long long`.)

- **Current:** `printf("%lld",4294967296LL)` prints `0` (low dword) instead of `4294967296`.
- **Expected (BCC 4.52):** `printf` prints the full 64-bit value for `%ll`.
- **Blocks:** Correctness of any code printing 64-bit integers; none of the tracked OWL gates exercise it yet — a latent silent-wrong path.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RTL-03** — severity medium, type bug, effort M, status new.

- **Evidence:** `src/codegen/expr.rs:117` (length modifiers h/l/L/j/z/t consumed and ignored); `src/codegen.rs:17211-17244` (`%d/%i/%u/%x` paths format via `fmt_int_spec`); `src/codegen.rs:17547,17554` (`fmt_int`/`int_token` format from 32-bit only); `src/codegen.rs:17485-17488` (Win64 explicitly narrows via `movsxd`/`mov eax,eax` before the 64-bit div loop).
- **Proposed acceptance oracle (set at Gate 1):** `printf("%lld",4294967296LL)` prints `4294967296` on `-m64`; an i386/x64 regression asserts the bytes; if deferred, the call errors cleanly rather than miscompiling.
