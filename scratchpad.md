# Scratchpad

Out-of-scope observations to triage later.

- [ ] 2026-09-22: trunk is not rustfmt-clean: `cargo fmt --all --check` reports ten files untouched by
  recent tasks (seen while landing src/overlay.rs). Decide whether to land one fmt-only commit and
  add `cargo fmt --check` to the integrate hygiene list.
- [ ] 2026-09-22: `build_bc45_libs` (src/bin/build_bc45_libs.rs:run_jobs) prints only
  per-group skip counts, never the failing units. SEM-04 hid for three months as
  OWL `skip=13` until RailC failed to link. Name the skipped units, or pin the
  expected-skip set so a newly failing unit (WINDOW, GDIBASE) is loud.
- [ ] 2026-06-17: Stock BC4.52 `OWLAPI/STATIC/STATICX.CPP` can reach
  `Static Control Tester` in Win64 product mode, but also intermittently exits
  with `0xC0000374` heap corruption before or during close. Repro by generating
  the same manifest shape as `tests/owl_examples_product.rs` for
  `wrk_oracle/bc452/BC45/EXAMPLES/OWL/OWLAPI/STATIC/STATICX.CPP`, then launch
  the built GUI under a bounded window smoke.
- [ ] 2026-06-17: Additional stock OWL product probes still expose generality
  gaps beyond the tracked BUTTON/INSTANCE gate: `OWLAPPS/HELLO/HELLOAPP.CPP`
  builds but exits `0xC0000005` before a top-level window; `OWLAPI/GROUPBOX` and
  `OWLAPI/EDIT` fail constructor overload resolution; `OWLAPI/GAUGE`,
  `LISTBOX`, `COMBOBOX`, and `SLIDER` link with unresolved OWL/GDI helper
  symbols; `OWLAPI/POPUP` builds but exits `0xC0000005` before a window. Repro
  with the same generated Win64 manifest shape used by
  `tests/owl_examples_product.rs`.
