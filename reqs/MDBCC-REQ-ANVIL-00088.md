# MDBCC-REQ-ANVIL-00088 — mdlink does not dispatch or apply `.def` module-definition files

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
mdlink must dispatch a `.def` input through the existing parser and apply it — at minimum `STACKSIZE`/`HEAPSIZE`→stack reserve/commit, `EXETYPE`→subsystem, and `EXPORTS`→PE export directory — matching the subset MAKEFILE.GEN emits. (The parser is done; remaining work is dispatch, apply, and export-dir emission.)

## Rationale
The `.def` parser exists and is tested, but it is unwired: mdlink has no `.def` extension branch (a `.def` becomes `CoffBytes` and fails COFF decode), the `Input::DefFile` path hard-returns an error, there is no PE export-directory emission, `LinkOpts` has no exports field, and parsed `STACKSIZE`/`HEAPSIZE` are never applied.

- **Current:** A `.def` input is unhandled and fails to decode; module-definition `EXPORTS`, stack/heap sizing cannot be expressed the BC4.52 way (mdbcc.toml has no exports field either).
- **Expected (BCC 4.52):** TLINK32 consumes a `.def` to set subsystem (`EXETYPE WINDOWS`), `STACKSIZE`/`HEAPSIZE`, and the export table (`EXPORTS name @ord`) — the only portable way BC4.52 declares DLL exports.
- **Blocks:** Building BC4.52 DLLs (the SYSTEM=WIN32 MODEL=d examples) — DLL EXPORTS / export directory is explicitly S8-deferred; 32-bit EXE samples are served by the default `LinkOpts`.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-08** — severity low, type missing-feature, effort L, status new.

- **Evidence:** `src/bin/mdlink.rs:93-109` (dispatches `.lib`/`.res`/else `CoffBytes`, no `.def` branch); `src/link/defparse.rs` is a complete, tested parser (NAME/DESCRIPTION/STACKSIZE/HEAPSIZE/EXPORTS, 16 tests); `src/link/mod.rs:388` hard-returns `LinkError::Internal` for `DefFile`; export-dir / EXPORTS deferred to S8 per `mod.rs:291-293` and `defparse.rs:33-35`; oracle `EXAMPLES/MAKEFILE.GEN:660-693` passes a generated `.def` as the TLINK32 5th positional; STACKSIZE/HEAPSIZE annotated 16-bit-only at `MAKEFILE.GEN:301/305`.
- **Proposed acceptance oracle (set at Gate 1):** Linking with a `.def` containing `EXPORTS Foo` yields a DLL whose export directory lists `Foo`; a `STACKSIZE` in the def changes the PE stack reserve.
