# MDBCC-REQ-ANVIL-00047 — Win32 imports resolved by hand-curated allowlist, not an import library

- **State:** Draft
- **Priority:** Must
- **Area:** Linker / archives / CRT
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Resolve Win32 imports by reading an import library (the BC45 IMPORT32.LIB or a generated equivalent) so any symbol it exports links without being pre-listed in source, falling back to `WIN32_IMPORTS` only as a seed.

## Rationale
Every importable Win32 API must be pre-registered (name→DLL) in a literal ~80-row table over a closed DLL set (KERNEL32/USER32/GDI32/COMDLG32); any API not in the table is a hard link error, since there is no import-library reader.

- **Current:** A symbol absent from `WIN32_IMPORTS` never resolves; the link fails with "no known DLL" / unresolved `__imp_`. This is always a clean hard link error (only triggered when codegen actually emits `__imp_<API>`), never a silent miscompile.
- **Expected (BCC 4.52):** tlink32 resolves `__imp_`/named imports against the supplied import libraries; IMPORT32.LIB carries the entire USER32/GDI32/KERNEL32/COMDLG32/COMCTL32/SHELL32/… export surface (name→ordinal→DLL), so any exported API links without the linker knowing it a priori.
- **Blocks:** S6 stock-OWL-sample generality (any sample touching an unlisted Win32 API); long-tail OWL/RTL closure completeness.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LNK-01** — severity high, type missing-feature, effort XL, status new.

- **Evidence:** `src/link/pe_writer.rs:97` (`const WIN32_IMPORTS`); `src/link/pe_writer.rs:1170-1178` (`used_dlls` → `import '{name}' has no known DLL`); `src/link/pe_writer.rs:4162-4170` (`build_idata_from_objects` → `LinkError::UnresolvedExternals(__imp_<name>)`); oracle ships the real answer at `wrk_oracle/bc452/BC45/LIB/IMPORT32.LIB`.
- **Proposed acceptance oracle (set at Gate 1):** Linking an object referencing an arbitrary IMPORT32.LIB export absent from `WIN32_IMPORTS` produces a valid `.idata` descriptor for the correct DLL and the EXE loads. (Note: this resolves only the Win32-import subset of the scratchpad GAUGE/LISTBOX/COMBOBOX/SLIDER "unresolved helper" class; OWL `.obj` symbols not produced by `build_bc45_libs` are a separate library-closure gap.)
