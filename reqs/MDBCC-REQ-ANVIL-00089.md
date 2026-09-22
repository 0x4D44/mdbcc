# MDBCC-REQ-ANVIL-00089 — Manifest exposes no lib search dirs, map/debug, or optimisation/warning keys

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
Extend the manifest additively (keeping unknown-key rejection) with the minimal high-value knobs: a lib search-dir list (so `libs` can be bare names) and a debug/map toggle (surfacing the existing `LinkOpts.map`); defer optimisation/warning levels until a backend consumes them.

## Rationale
`mdbcc.toml` can set target/subsystem/defines/include+overlay dirs and explicit full-path libs only; there is no lib search-dir (every lib must be a full path), no map/debug toggle, and no optimisation/warning keys — and unknown keys are hard-rejected.

- **Current:** No way to request a linker map, set entry/stack/image-base, or add a library search directory; lib-by-name resolution does not exist (only header search via `SearchPathResolver`).
- **Expected (BCC 4.52):** Projects routinely vary optimisation (`-O*`), warnings (`-w*`), debug (`-v`), map generation (`-m`/`-s`), stack/heap, and resolve libs by name from a `LIB` search path; a faithful project system surfaces at least the load-bearing knobs.
- **Blocks:** Expressing real BC4.52 build configurations through mdbcc.toml and lib-by-name resolution for OWL/RTL/BIDS deps (ergonomics — every config is expressible via full paths today).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-09** — severity low, type incomplete, effort M, status new.

- **Evidence:** `src/project.rs:785-796` `KNOWN_KEYS` (plus `resource_profile`, `objects`); unknown-key error at `project.rs:797-803`; stack/entry/image-base hardcoded from target defaults `project.rs:396-398`; libs read directly as paths `project.rs:364-371`; grep `lib_dir|optimiz|warning|map` over `project.rs` finds none. Linker capability for two knobs already exists: `LinkOpts.map` (`link/mod.rs:64`, wired to `mdlink --map`) and `warnings_as_errors` (`link/mod.rs:47`, currently unused).
- **Proposed acceptance oracle (set at Gate 1):** A manifest with `lib_dirs=[...]` resolves `libs=["mdowl"]` by name; a `map=true` key writes a linker map next to the output; existing manifests still build unchanged.
