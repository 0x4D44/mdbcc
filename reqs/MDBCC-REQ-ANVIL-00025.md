# MDBCC-REQ-ANVIL-00025 — `long double` folded to 8-byte `double` miscompiles `%Lf`/`%Lg` and the long-double ABI

- **State:** Draft
- **Priority:** Must
- **Area:** Code generation — i386
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Represent `long double` as a distinct 10-byte (80-bit x87) type on i386 — parse it to a dedicated AST type, size it 10 bytes, store/load as tbyte (`fld`/`fstp`), and pass it as 10 stack bytes in cdecl/varargs. As an interim mitigation until full 80-bit support exists, reject `long double` in a varargs/`%L` context with a clean `CodegenError` rather than silently truncating.

## Rationale
`long double` is treated as a synonym for 8-byte `double`, so `sizeof(long double)==8` and varargs marshal only 8 bytes; the recompiled RTL reads a 10-byte value and over-advances the `va_list`, corrupting every following format argument.

- **Current:** `printf("%Lf", ld)` pushes 8 bytes; the recompiled RTL reads 10, so the value is wrong AND the `va_list` is desynced by 2 bytes, cascading corruption to all subsequent arguments. `sizeof(long double)` reports 8, so any aggregate with a `long double` member has the wrong layout/stride.
- **Expected (BCC 4.52):** 32-bit `long double` is the 80-bit x87 extended type occupying 10 bytes (`sizeof==10`, stack-passed as 10 bytes for varargs); `%Lf`/`%Lg`/`%Le` consume a 10-byte value.
- **Blocks:** Faithful recompilation of the RTL math/printf family and any in-scope TU using `long double` (S3/S4 real-source parity); parked B-21.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C32-01** — severity high, type spec-conformance, effort XL, status sharpens-parked.

- **Evidence:** `C:\language\mdbcc\src\parser.rs:1426-1428` (returns `Type::Float { bytes: 8 }` for `long double`); `C:\language\mdbcc\src\ast.rs:273` (sizes `Type::Float{bytes}` directly); `C:\language\mdbcc\src\codegen.rs:14820-14824` (marshals the arg as an 8-byte cell); RTL oracle `C:\language\mdbcc\wrk_oracle\bc452\BC45\SOURCE\RTL\SOURCE\IO\COMMON32\VPRINTER.C:607,613` (selects `F_10byteFloat`, advances via `__nextreal(argP, LongDoubleBit)`) and `...\MATH\COMMON32\REALCVT.C:330-337` (does `va_arg(argP, long double)`, +10 bytes).
- **Proposed acceptance oracle (set at Gate 1):** Compiling `printf("%Lf %d\n", (long double)1.5, 7)` against the recompiled RTL prints `1.500000 7` (value correct AND trailing int intact); `sizeof(long double)==10`; struct `{char c; long double d;}` matches bcc32 member offsets.
