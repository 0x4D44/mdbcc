# MDBCC-REQ-ANVIL-00048 — `.def` module-definition support parsed but unwired into the link path and driver

- **State:** Draft
- **Priority:** Should
- **Area:** Linker / archives / CRT
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Wire `defparse` into `link()`: route `.def` inputs (by extension and/or a `/DEF:` flag) through `defparse`, apply STACKSIZE/HEAPSIZE to `LinkOpts`, and carry EXPORTS into the export-table builder (see LNK-03).

## Rationale
A `.def` file cannot reach the linker: no extension routing, no CLI flag, and the wired `Input::DefFile` arm hard-errors. STACKSIZE/HEAPSIZE never override `LinkOpts`; EXPORTS are never honoured.

- **Current:** `.def`-parsed stack/heap/export values are dead code. (The stack/heap override sink already exists and works via the `--stack`/`/STACK` CLI flags → `LinkOpts` → `pe_writer.rs:3769-3777`; only the `.def`→`LinkOpts` wiring is missing, making this cheap.)
- **Expected (BCC 4.52):** tlink32 accepts a `.def` on the command line — NAME sets the module name, STACKSIZE/HEAPSIZE override stack/heap reserve+commit, and EXPORTS drives the export table for DLL output.
- **Blocks:** DLL output (LNK-03); any TU/sample relying on a `.def` for stack/heap sizing or exports.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LNK-02** — severity medium, type incomplete, effort M, status new.

- **Evidence:** `src/link/defparse.rs` parses NAME/DESCRIPTION/STACKSIZE/HEAPSIZE/EXPORTS (392 lines) but `defparse::parse` is called only from its own tests; `src/link/mod.rs:388-393` returns `LinkError::Internal("…not yet supported (S1c.9 work…)")`; `src/bin/mdlink.rs` has no `--def`/`/DEF:` flag and `src/bin/mdlink.rs:99-109` classifies any non-.lib/.res positional as `Input::CoffBytes` (a `.def` would fail COFF decode).
- **Proposed acceptance oracle (set at Gate 1):** Passing a `.def` with `STACKSIZE 0x200000` / `HEAPSIZE 0x100000` changes the PE optional-header `SizeOfStackReserve`/`SizeOfHeapReserve` accordingly, an EXPORTS-bearing `.def` feeds the export table, and a regression covers `.def`→`LinkOpts` override.
