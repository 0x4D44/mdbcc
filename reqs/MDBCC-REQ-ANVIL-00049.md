# MDBCC-REQ-ANVIL-00049 — No DLL / export-table (`.edata`) output; linker produces EXEs only

- **State:** Draft
- **Priority:** Should
- **Area:** Linker / archives / CRT
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add DLL output: build an `.edata` export directory from the `.def` EXPORTS list (name/ordinal/NONAME/DATA), set `IMAGE_FILE_DLL`, and emit a DllMain entry stub; scope to what the OWL static path needs and track the deferral (e.g. in BUGS.md Parked as an S8 item).

## Rationale
The writer emits only `IMAGE_SUBSYSTEM_WINDOWS_{CUI,GUI}` executables: no `IMAGE_FILE_DLL` characteristic, no export directory, no DllMain entry shape, no ordinal/name export table.

- **Current:** EXPORTS is parsed into a well-modelled `DefExport` (name/internal/ordinal/noname/data) but never consumed; the linker cannot produce a DLL.
- **Expected (BCC 4.52):** tlink32 produces DLLs (the BC45 OWL/BIDS ship as both static and DLL forms) with an export table built from `.def` EXPORTS, `IMAGE_FILE_DLL` set, and a DllMain-shaped entry.
- **Blocks:** DLL-form OWL/BIDS/RTL deliverables and future S8 DLL packaging; the mission targets static EXEs, so off the critical path.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LNK-03** — severity medium, type missing-feature, effort XL, status new.

- **Evidence:** No export-table code (export/edata/`IMAGE_DIRECTORY_ENTRY_EXPORT`/`IMAGE_FILE_DLL`/DllMain) anywhere in `src/link/pe_writer.rs` (only import-side `__imp_` handling at `pe_writer.rs:3520,4156`); `src/link/defparse.rs:33-35` documents the EXPORTS field as "Stored for S8 DLL output; the linker does nothing with them today"; `LinkOpts` (`src/link/mod.rs:29`) has no dll/exports field.
- **Proposed acceptance oracle (set at Gate 1):** Linking with a `.def` EXPORTS list and a DLL flag yields a loadable DLL whose export directory `GetProcAddress`-resolves the listed names/ordinals, verified by loading the DLL and resolving an export.
