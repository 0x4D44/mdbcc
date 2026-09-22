# MDBCC-REQ-ANVIL-00087 — mdar does not accept TLIB operation syntax (`+`/`-`/`*`)

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
mdar must accept the TLIB positional grammar `mdar <lib> {+|-|*}<module>...`, adding/removing/extracting members of an existing or new archive, in addition to the current `-o` convenience form.

## Rationale
mdar accepts only `-o/--out <lib>` plus bare positional object paths with replace/full-rebuild semantics; there is no `+`/`-`/`*` operation parser and no incremental add/remove/extract.

- **Current:** `mdar mylib.lib +array.obj +myclass.obj` treats `+array.obj` as a filename (open fails); there is no incremental update.
- **Expected (BCC 4.52):** TLIB grammar — first positional is the library; subsequent tokens are `+module` (add/replace), `-module` (remove), `*module` (extract), `-+`/`+-` (replace), optionally with a response file and listing file (`, listfile`) — updating an existing archive in place rather than always rebuilding.
- **Blocks:** Running stock BIDS/OWL LIBBIN rules and TLIB-driven BC4.52 library builds (off the native build path — `build_bc45_libs.rs` enumerates objects itself and calls `mdar -o`).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-07** — severity low, type missing-feature, effort L, status new.

- **Evidence:** `src/bin/mdar.rs:23-45` (only `-o`/`--out` plus positionals, every positional added, full rebuild); oracle `EXAMPLES/MAKEFILE.GEN:866-869` `$(TLIB) $(LIBBIN) $(_LIBOBJ_)` where `_LIBOBJ_` (lines 638-642) is `+obj1+obj2...`.
- **Proposed acceptance oracle (set at Gate 1):** A test creates a lib with `+a.obj +b.obj`, then `mdar lib.lib -a.obj +c.obj` and asserts the member set is `{b,c}`; extraction `*b.obj` writes `b.obj` to disk.
