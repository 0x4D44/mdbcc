# MDBCC-REQ-ANVIL-00085 — bcc rejects standard BC4.52 compiler flags rather than accepting-as-noop

- **State:** Draft
- **Priority:** Could
- **Area:** Driver / CLI / project
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
bcc must recognise the BC4.52 compiler flags stock makefiles pass, either implementing them or explicitly accepting-as-noop with a documented diagnostic, rather than failing the whole compile on an unknown flag. (`-O*` optimisation and `-v` debug-info generation are out of mdbcc's current scope; accept-as-noop is the realistic ask.)

## Rationale
bcc hard-errors any unrecognised `-` token, so the stock makefile flags (`-W`/`-WD*`/`-WS` target+model, `-O*`/`-Od` optimisation, `-v` debug, `-w*` warnings, `-d`/`-k*` codegen) all fail the compile rather than being implemented or ignored.

- **Current:** `bcc -c -W -O1gmpv -v -d -k- -D_RTLDLL foo.cpp` fails on the first `-W`.
- **Expected (BCC 4.52):** BCC32 accepts these flags; several affect codegen (`-O*`, `-v`) but many are no-ops for a 32-bit single-model target. A drop-in compiler must at least accept-and-ignore the benign ones with a documented diagnostic.
- **Blocks:** Compiling a TU with the flags a stock BC4.52 makefile emits (off the native build path, which constructs its own argv).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-05** — severity low, type incomplete, effort M, status new.

- **Evidence:** `src/main.rs:99-102` (unrecognised `-` token is a hard "unknown option" error); accepted set `main.rs:56-104` (only `--dump-tokens`, `-E`, `-c`, `-m32/-m64`, `-o`, `-I`, `-D`, `-h`); oracle `EXAMPLES/MAKEFILE.GEN:489-547` CFLAGS `-W -WDE/-WS -O1gmpv/-Od -v -d -k/-k- -w $(CDIAG) -D_RTLDLL`.
- **Proposed acceptance oracle (set at Gate 1):** `bcc -c -W -O1gmpv -v -d -k- -D_RTLDLL foo.cpp` produces `foo.obj` (with a note for any ignored flag); a test feeds the literal CFLAGS string from MAKEFILE.GEN.
