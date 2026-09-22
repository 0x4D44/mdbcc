# MDBCC-REQ-ANVIL-00061 — Core math.h functions unresolvable (asm-only source, no intrinsic, no shim)

- **State:** Draft
- **Priority:** Must
- **Area:** RTL / CRT / iostreams
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Provide working implementations of at least sqrt, fabs, floor, ceil, fmod, sin, cos, tan, atan, atan2, exp, log, pow, hypot, ldexp, frexp, modf reachable from in-scope C/C++ — either as codegen intrinsics (fabs/floor/ceil/sqrt are single x87 ops: `fabs`, `frndint` with rounding mode set, `fsqrt`; sin/cos/tan/atan/exp/log/pow need fsin/fcos/fpatan/f2xm1/fyl2x sequences) or a small polynomial C core compiled into `mdcw32.lib`, mirroring the memmove/strchr shim approach. Both `-m32` (x87) and `-m64` (SSE2 has no transcendentals — still needs x87 or a software/poly core) must be covered.

## Rationale
Every floating-point `math.h` function (sin/cos/tan/sqrt/pow/exp/log/atan/fabs/floor/ceil/fmod/hypot, plus ldexp/frexp/modf) is unreachable — the RTL ships these bodies only as `.ASM`, which the library builder filters out, and there is no codegen intrinsic or shim substitute.

- **Current:** A program calling any of these links with an unresolved external symbol — the `.ASM`-defined RTL function never enters `mdcw32.lib` and nothing substitutes it.
- **Expected (BCC 4.52):** These resolve from MATHL.LIB/the FP RTL: `sqrt(2.0)==1.41421356…`, sin/cos/exp/log return correctly-rounded x87 results. They are core C runtime.
- **Blocks:** Stock OWL samples METEOR (GAMES), ACLOCK, GDIDEMO/LINE, MTHREAD/LINE, TUTORIAL/CNTRL16/17 — the S6/S7 sample frontier.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RTL-01** — severity high, type missing-feature, effort L, status new.

- **Evidence:** `wrk_oracle/bc452/BC45/SOURCE/RTL/SOURCE/MATH/COMMON32` (SIN.ASM, COS.ASM, TAN.ASM, SQRT.ASM, POW.ASM, EXP.ASM, LOG.ASM, ATAN.ASM, FABS.ASM, FLOOR.ASM, CEIL.ASM, FMOD.ASM, HYPOT.ASM — `.ASM` only, never `.C`); `src/bin/build_bc45_libs.rs:808` (`c_or_cpp_sources` compiles only `.C`/`.CPP`, silently dropping `.ASM`); `src/codegen/expr.rs:174` (`libc_ret` covers only strlen/strcmp/memcmp/abs/atoi/strcpy/strcat/memcpy/memset — no transcendentals); `wrk_rtlshim/rtlshim.c` (provides only `_control87`/`_qmul10`/`_fuildq`/`rand`).
- **Proposed acceptance oracle (set at Gate 1):** `printf("%f", sqrt(2.0)+sin(0.0)+floor(3.7));` links and runs producing `1.414214` (or bcc32-matching digits) for both `-m32` and `-m64`; the METEOR sample's atan(1)/sin/cos sinTable build links.
