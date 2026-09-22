# MDBCC-REQ-ANVIL-00013 — Inline asm bodies are silently dropped with no diagnostic

- **State:** Draft
- **Priority:** Should
- **Area:** Parser — C language
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
When an asm block is dropped, record a diagnostic (a warning, or a `CodegenError` for an asm-only body whose removal changes the return value) identifying the function and source location.

## Rationale
An `asm`/`__asm` block is parsed and discarded to `Stmt::Empty` with no warning; an asm-only or asm-side-effect-bearing function silently loses behaviour, returning an undefined value with no diagnostic.

- **Current:** Inline asm is accepted and silently dropped. The asm-only-RTL-primitive case is largely routed around by C shims (`wrk_rtlshim/rtlshim.c`), but a function mixing C with a load-bearing asm side effect (sets the return register, modifies a flag/memory the C reads) silently loses that effect, and no diagnostic is emitted.
- **Expected (BCC 4.52):** bcc32 would emit the asm; mdbcc cannot honour x86 asm on Win64, but dropping it must be loud — a dropped asm body must never be a silent miscompile.
- **Blocks:** Trustworthy compilation of any RTL/CRT primitive bearing load-bearing asm side effects (S5); avoiding silent runtime corruption from dropped asm.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSC-04** — severity medium, type diagnostics, effort S, status new.

- **Evidence:** `src/parser.rs:6881-6884` (returns `Stmt::Empty`); `src/parser.rs:6829-6872` (`skip_inline_asm` balances and discards tokens); the parser has no warnings mechanism on this path.
- **Proposed acceptance oracle (set at Gate 1):** Compiling `int f(){ __asm { mov eax, 1 } }` produces a diagnostic naming `f` and the asm location; a test asserts the diagnostic is present (or that an asm-only body is a clean `CodegenError`, not a silently-empty function).
