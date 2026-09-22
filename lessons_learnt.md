# Lessons learnt

<!-- lessons-format: index-v1 -->
<!-- Each entry's FIRST line is a self-contained nugget: surprise + fix + file:symbol
pointer, <=~120 chars, plain text (no backticks). Indented continuation lines are detail —
kept here for lookup but NOT injected by the mdminder SessionStart hook (it injects the
nugget lines only). Add new lessons at the TOP (newest-first). NEVER drop a lesson to make
room - always prepend. Aim for ~25 entries; past ~40 say it is due a prune rather than
pruning unasked, since /prune-lessons-learnt is a separate human-invoked pass. The hook
injects only the newest 30 nuggets (or 4 KiB), so entries past that stay here for lookup
and cost a session nothing. Durable project facts belong in CLAUDE.md (repo) or
~/.claude/CLAUDE.md (global), not here. -->

- 2026-09-22: PE subsystem version >= 6.0 changes USER frame and dialog metrics; keep 3.10 (pe_writer.rs SUBSYSTEM_VERSION)
  At 6.0 RailC's fixed-pixel boards lost 10px of client and the About dialog
  shrank 87px. When a GUI looks "laid out wrong" versus the Borland build,
  compare header fields before hunting codegen: patch a copy and re-measure.
- 2026-09-22: Static-ness is per overload, not per name; derived ClassInfo inherits method NAMES only (parser.rs ClassInfo::is_static_overload)
  OWL mixes static and instance overloads (TGdiBase::CheckValid). Keying static by
  name dropped `this` from the instance overload; build_bc45_libs then skipped the
  unit silently and the break surfaced only as unresolved externals at RailC link.
- 2026-06-19: External C corpora hold non-UTF8 source bytes; byte-preserve or exclude those fixtures at the corpus boundary
  Raw char-literal/string test data is the usual case. String-based differential
  adapters should exclude or byte-preserve those fixtures at the corpus boundary,
  not lossy-decode them into false compiler reds.
- 2026-06-19: Task worktrees do not inherit gitignored oracle assets (wrk_oracle/bc452); emit loud env-skip rows instead
  Product-path oracle tests in a clean worktree should report loud `env-skip` rows
  unless the BC4.52 tree/libs are mirrored there.
- 2026-06-17: Tiny compute_emitted but multi-second codegen means a pre-emission full-TU pass; index inline defs by final symbol
  If a RailC/OWL TU has tiny emitted reachability (`compute_emitted` says a handful
  of functions) but multi-second `codegen`, inspect pre-emission full-TU passes
  before body lowering. The W6/G4 culprit was extern-prototype/inline collision
  detection repeatedly scanning all items and re-running final-symbol mangling per
  prototype; indexing inline defs by final symbol cut RailC serial codegen from
  ~61s to ~1.25s.
- 2026-06-17: Win64 OWL: separate link-root from runtime ABI failures; a cp==1 string crash means implicit this on statics
  For Win64 OWL example bring-up, separate **link-root** failures from **runtime
  ABI** failures. A GUI app may need `WinMain` seeded into archive scanning even
  when no object references it yet; after link succeeds, an early
  `string(const char*)` crash with `cp == 1` points at out-of-line static member
  definitions being emitted with an implicit `this` (e.g.
  `TApplication::SetWinMainParams`), not at OWL static constructors.
- 2026-06-17: mdscreensnap is blank in agent sessions; capture per window with PrintWindow under PowerShell 5.1 (uibug_probe.ps1)
  **Debugging Win64 OWL GUI rendering**: full-screen `mdscreensnap` returns a
  blank/white frame in agent sessions (no live desktop). Capture per **window**
  with `PrintWindow` under **Windows PowerShell 5.1** (`powershell.exe`,
  `System.Drawing`) — pwsh 7 fails on `System.Drawing.Common`. Pair it with an
  `EnumChildWindows`/`GetWindow` **window-tree dump** (id/class/text/rect/style/
  z-order); comparing that tree against the 32-bit `gui_parity/golden_run`
  oracle isolates layout/data bugs from pure paint bugs (e.g. an overlapping
  `SS_BLACKRECT` without `WS_CLIPSIBLINGS` paints over text — F-27). Reusable
  harness: `wrk_probe/owl_win64_smoke/uibug_probe.ps1` (drives RailC to any
  dialog via `PostMessage WM_COMMAND <cmd>`).
- 2026-06-16: A Win64 OWL app via mdbcc.toml needs BOTH win64 dep libs and overlay_dirs include64, or it fails confusingly
  (1) Win64 dep libs: `cargo bc45-libs-win64` → `target/bc45-libs/win64/`; the
  default `-m32` libs give a link-time `machine mismatch ... expected Amd64, got
  I386`. (2) `overlay_dirs = ["…/wrk_owl_win64/include64"]` in the app manifest so
  the app's own TUs share the 64-bit `WPARAM`/`LPARAM`/`LRESULT` ABI with the libs
  — without it you get cross-TU dispatch-mangling mismatches at link, or `lParam`
  pointer truncation (`0xC0000005`) at runtime. The validated recipe lives in
  `tests/railc_source_slice.rs::railc_source_built_dependency_slice_links_win64`.
- 2026-06-16: RTL EXCEPT.C needs WINVER=0x030A before INCL_USER parses, then _EAX/_EDX feed ___doGlobalUnwind via registers
  RTL `EXCEPT/COMMON32/EXCEPT.C` needs `WINVER=0x030A` before the `INCL_USER`
  headers parse, then its `_EAX`/`_EDX` assignments feed `___doGlobalUnwind`
  through real registers; diagnose both layers together.
