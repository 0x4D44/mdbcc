# MDBCC-REQ-ANVIL-00054 — No INCLUDE search path; angle-bracket `<...>` includes rejected

- **State:** Draft
- **Priority:** Must
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Thread an include-search-path list (from a new mdrc `-I` option and the project's `overlay_dirs`/INCLUDE) through `rc::compile_file` → `pp::preprocess`; accept `#include <file>` searching the path, and fall back to the path for `"file"` misses.

## Rationale
The `#include` handler accepts only the `"file"` form resolved relative to the including file; angle-bracket `<owl\...>`/`<windows.h>` includes are a fatal error, and no INCLUDE/`-I`/overlay search path is threaded into the RC preprocessor.

- **Current:** Angle-bracket includes are a fatal error; even quoted includes resolve only relative to the file's own directory.
- **Expected (BCC 4.52):** BRC32 resolves `#include <name>` against its INCLUDE search path (where BC4.52 ships `owl\*.rc`, `*.rh`, and `windows.h`) and resolves `#include "name"` relative to the file first, then the search path.
- **Blocks:** S6 OWL sample apps; any `.rc` using `<windows.h>` or `<owl\...>` includes.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-02** — severity high, type missing-feature, effort M, status new.

- **Evidence:** `src/rc/pp.rs:62-67` (quote-only check), `src/rc/pp.rs:69` (`dir.join(rel)` relative resolution); `src/rc/mod.rs:458` and `src/project.rs:326` take only `(path, defines)`; oracle `EXAMPLES/OWL/OWLAPI/COMBOBOX/COMBOBXX.RC:6,9`, `LISTBOXX.RC:4`, `GAUGEX.RC:5`. Note `project.rs:131` already carries `overlay_dirs` but does not pass it to `rc::compile_file`.
- **Proposed acceptance oracle (set at Gate 1):** `mdrc -I <bc45>/INCLUDE foo.rc` where `foo.rc` does `#include <owl\inputdia.rc>` resolves and compiles; project builds pass overlay/include dirs so an OWL sample's resources compile from source.
