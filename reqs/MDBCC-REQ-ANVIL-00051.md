# MDBCC-REQ-ANVIL-00051 — mdar cannot read OMF objects or modify existing libraries (no TLIB ops)

- **State:** Draft
- **Priority:** Could
- **Area:** Linker / archives / CRT
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add OMF ingestion (reuse `omf::read_to_coff` for pubdef extraction) and at minimum list (`-t`) plus add-to-existing-lib operations, so mdar can manipulate and inspect real Borland libraries.

## Rationale
mdar is create-only and COFF-only — it cannot ingest a bcc32-produced OMF object, nor add/remove/extract/list members of an existing `.lib`.

- **Current:** mdar only ingests mdbcc-produced COFF `.obj` files and only writes a brand-new archive; it cannot round-trip a Borland OMF `.lib` or inspect/maintain one. (`omf::read_to_coff` and `member_pubdefs_with_storage` already exist for pubdef extraction; the genuinely new surface is reading an MS-format archive back into members.)
- **Expected (BCC 4.52):** TLIB supports add (`+`), remove (`-`), replace (`-+`), extract (`*`), and list operations on existing libraries, with Borland `.OBJ`/`.lib` inputs being OMF.
- **Blocks:** none on the from-source build path (mdbcc emits COFF); blocks interop with precompiled Borland OMF libs and library inspection/maintenance workflows.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LNK-05** — severity low, type incomplete, effort M, status new.

- **Evidence:** `src/bin/mdar.rs:67` reads each input strictly via `coff::Object::read` and errors "is not a COFF object" (no `omf::read_to_coff` fallback); `src/bin/mdar.rs:30` shows the tool always builds a fresh archive (`mdar -o out.lib <obj>…`) with no `+`/`-`/`*`/list operations.
- **Proposed acceptance oracle (set at Gate 1):** mdar can list the members/symbols of an existing `.lib` and add an OMF `.obj` to it; the resulting lib links via mdlink; a regression covers OMF-member add + list.
