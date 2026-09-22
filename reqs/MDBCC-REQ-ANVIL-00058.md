# MDBCC-REQ-ANVIL-00058 — CURSOR / RT_GROUP_CURSOR resource unsupported

- **State:** Draft
- **Priority:** Should
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add the CURSOR top-level resource — lexer keyword, parser cooking of the `.cur` into RT_CURSOR image bytes + RT_GROUP_CURSOR metadata (hotspot handling included), and `res.rs` writer/RT constants — mirroring the ICON implementation.

## Rationale
There is no `CURSOR` lexer keyword and no `RT_CURSOR`(1)/`RT_GROUP_CURSOR`(12) constants or cooking path; mdrc cannot emit cursor resources.

- **Current:** A `<id> CURSOR "file.cur"` statement lexes CURSOR as a bare Ident and fails as an unrecognised top-level resource.
- **Expected (BCC 4.52):** BRC32 compiles CURSOR into RT_CURSOR image bytes plus an RT_GROUP_CURSOR directory entry, analogous to the ICON cooking, with the `.cur` hotspot prepended to the RT_CURSOR image as two leading `u16`s.
- **Blocks:** OWL samples that ship custom cursors (14 CURSOR statements in the example corpus).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-06** — severity medium, type missing-feature, effort M, status new.

- **Evidence:** `src/rc/lexer.rs:625-677` (no `cursor` keyword), `src/rc/res.rs:49-68` (RT constants omit RT_CURSOR/RT_GROUP_CURSOR); 14 `<id> CURSOR` statements across EXAMPLES (incl. OWL samples PAINT and SWAT). The existing ICON path (`parse_icon_resource` → `cook_ico_payload` → RT_ICON + RT_GROUP_ICON, `res.rs:181/346`) is the template.
- **Proposed acceptance oracle (set at Gate 1):** `<id> CURSOR "x.cur"` produces RT_CURSOR + RT_GROUP_CURSOR `.res` entries that brc32-diff clean and load via `LoadCursor` at runtime.
