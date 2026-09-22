# MDBCC-REQ-ANVIL-00066 — setjmp/longjmp unprovided (asm-only source, no intrinsic, no shim)

- **State:** Draft
- **Priority:** Could
- **Area:** RTL / CRT / iostreams
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Provide `setjmp`/`longjmp` — either a small target-specific codegen intrinsic that saves/restores the callee-saved regs + SP + return address into the `jmp_buf`, or document it as out-of-scope for the OWL mission (OWL uses C++ EH, not setjmp). The cheapest valid resolution is a BUGS/scratchpad entry recording deliberate non-support with the asm-only rationale.

## Rationale
`setjmp`/`longjmp` are declared as real RTL functions but defined only in `SETJMP.ASM`, which the library builder drops; there is no codegen intrinsic and no shim provider.

- **Current:** A program using non-local jumps fails to link (unresolved `_setjmp`/`longjmp`); there is no intrinsic to materialize the `jmp_buf` save/restore. This is a loud link failure, but currently undocumented.
- **Expected (BCC 4.52):** `setjmp`/`longjmp` are provided; non-local jumps work.
- **Blocks:** In-scope C programs using non-local jumps; not on the tracked OWL gate path (low priority), but currently an undocumented hard link failure.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RTL-06** — severity low, type missing-feature, effort M, status new.

- **Evidence:** `wrk_oracle/bc452/BC45/SOURCE/RTL/SOURCE/PROCESS/WIN32/SETJMP.ASM` (the only definition — no `.C`); `build_bc45_libs` compiles only `.C`/`.CPP`; no `setjmp`/`longjmp` entry in `wrk_rtlshim/`; the external corpus adapter already bans `setjmp` (line 161) as out-of-corpus.
- **Proposed acceptance oracle (set at Gate 1):** A setjmp/longjmp round-trip returns the longjmp value; or a scratchpad/BUGS entry records the deliberate non-support with the asm-only rationale.
