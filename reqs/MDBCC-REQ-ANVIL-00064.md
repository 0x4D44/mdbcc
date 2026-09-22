# MDBCC-REQ-ANVIL-00064 — printf is literal-format-only with no fallback to the real Borland printf

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
When the format string is non-literal or uses an unsupported conversion, fall back to the real source-built Borland `printf`/`vprintf` symbol in `mdcw32.lib` — emit a normal call to `_printf` and let the linker pull PRINTF.C — rather than making the intrinsic the only path.

## Rationale
`printf`/`puts` are unconditionally intercepted and lowered to inlined WriteFile sequences; a non-literal (runtime) format string or any unsupported conversion (`%e`/`%g`/`%E`/`%G`/`%n`/`%.Nd`) is a hard compile error, even though the real Borland `printf`/`vprintf` is built into `mdcw32.lib`. There is no codegen path that emits a real `_printf` call.

- **Current:** `printf(fmt,…)` with a runtime `fmt` fails to compile; `printf("%g",x)`, `printf("%e",x)`, `printf("%.3d",n)`, `printf("%n",&c)` all fail to compile.
- **Expected (BCC 4.52):** `printf` accepts any (runtime or literal) format string and the full conversion/precision set.
- **Blocks:** Any in-scope C program that builds format strings at runtime or uses `%e`/`%g`/`%.Nd`; broadens beyond the literal-only corpus.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RTL-04** — severity medium, type incomplete, effort M, status new.

- **Evidence:** `src/codegen.rs:17152-17158` (non-`Str` format → `CodegenError`); `src/codegen.rs:12322-12324` (interception precedes the `is_builtin`/shadowing check at 12330, so it is truly unconditional); `src/codegen/expr.rs:127` (rejects `%e/%g/%E/%G`); `src/codegen.rs:17208` (`int_prec_err` rejects `%.Nd`); PRINTF.C/VPRINTF.C compile into `mdcw32.lib` but user code never references the symbol.
- **Proposed acceptance oracle (set at Gate 1):** A test with `const char*f=cond?"%d":"%x"; printf(f,n);` compiles, links (pulling PRINTF.C), and prints correctly; `printf("%g",1.5)` routes to the real formatter.
