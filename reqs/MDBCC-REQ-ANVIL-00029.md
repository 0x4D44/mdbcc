# MDBCC-REQ-ANVIL-00029 — float→unsigned-32 conversion uses signed `cvttsd2si` (wrong for values ≥ 2³¹)

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
For a float→unsigned-32 destination, perform the truncating convert into a 64-bit register (`cvttsd2si rax`) and take the low 32 bits, so the full unsigned-int range round-trips correctly; leave the signed-int path unchanged.

## Rationale
A float→integer conversion to an unsigned 32-bit destination emits a 32-bit signed `cvttsd2si` and retags the source as signed, so a source value in [2³¹, 2³²) saturates to the x86 integer-indefinite `0x80000000` instead of the correct unsigned value.

- **Current:** `(unsigned int)d` for a double in [2147483648, 4294967295] yields `0x80000000` instead of the correct in-range unsigned result — a silent miscompile.
- **Expected (BCC 4.52):** Yields the correct unsigned value for in-range doubles; the standard sequence is a 64-bit `cvttsd2si rax` then truncate to the low 32 bits, exact across the whole unsigned-32 range.
- **Blocks:** none (rare numeric C code converting large doubles to unsigned int; correctness completeness of S2 conversions).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C32-05** — severity medium, type bug, effort S, status new.

- **Evidence:** `C:\language\mdbcc\src\codegen.rs:12208-12219` — emits `Cvttsd2si reg32` whenever `to.size() != 8`, then retags `from` as a signed 4-byte int regardless of the destination's signedness; the unsigned 4-byte to-arm falls through (`_ => {}`) leaving eax untouched.
- **Proposed acceptance oracle (set at Gate 1):** An i386 test converting `3000000000.0` to `unsigned int` yields `3000000000` (not `0x80000000`); signed-int conversion unchanged.
