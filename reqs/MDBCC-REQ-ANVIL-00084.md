# MDBCC-REQ-ANVIL-00084 — mdlink rejects native TLINK32 flag and comma-positional syntax

- **State:** Draft
- **Priority:** Could
- **Area:** Driver / CLI / project
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
mdlink must accept the BC4.52 TLINK32 flag spellings real makefiles emit (`-Tpe`/`-Tpd`, `-aa`/`-ap`, `-c`, `-x`, `-v`) and the comma-positional input grammar, mapping them onto the existing `LinkOpts`.

## Rationale
mdlink accepts only GNU/MSVC flag spellings and hard-errors every TLINK32 flag (`-Tpe`/`-Tpd`, `-aa`/`-ap`, `-c`, `-x`, `-v`); it also has no comma-separated positional grammar `objs,exe,map,libs`.

- **Current:** `mdlink -Tpe -aa -c -x -v c0w32.obj app.obj,app.exe,,libs` fails with "unknown option -Tpe"; the comma-positional grammar is unsupported.
- **Expected (BCC 4.52):** TLINK32 maps `-Tpe`→PE exe, `-Tpd`→PE DLL, `-aa`→GUI, `-ap`→console, `-c`→case-sensitive symbols, `-x`→no map, `-v`→debug info, and uses positional grammar `objfiles, exefile, mapfile, libfiles, deffile, resfiles`.
- **Blocks:** Running stock BC4.52 link rules verbatim (documented S8-deferred; nothing on the S0–S7 path emits literal TLINK32 LFLAGS).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-04** — severity low, type missing-feature, effort L, status sharpens-parked.

- **Evidence:** `src/bin/mdlink.rs:284-289` (unrecognised `-`/`/` token is a hard error); accepted set at `mdlink.rs:208-282`; oracle `EXAMPLES/MAKEFILE.GEN:504-508` `LFLAGS = -Tpe -aa -c $(LDBG)` / `-Tpe -ap -c` with `$(LDBG)=-v` and `_MAPEXE_ = -x` (line 709); the deferral to S8+ is documented at `mdlink.rs:11-13`.
- **Proposed acceptance oracle (set at Gate 1):** mdlink invoked with the literal `LFLAGS`/positional command MAKEFILE.GEN emits for a CON32 EXE produces a valid PE32+ with the right subsystem; unknown TLINK flags still error.
