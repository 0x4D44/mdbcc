# MDBCC-REQ-ANVIL-00069 — `TApplication` default-startup / `TFrameWindow` run path crashes 0xC0000005 before any window

- **State:** Draft
- **Priority:** Must
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
The OWL `TApplication` startup path — `InitApplication`/`InitInstance`/`InitMainWindow`/`Run` plus the `TFrameWindow` Create/Show and message-loop bring-up — must run to a live window on Win64 without an access violation (the true shared failure is the `TFrameWindow` run path, not solely the synthesized-default frame).

## Rationale
An OWL app that leans on `TApplication`'s default `InitApplication`/`InitInstance`/`InitMainWindow`/`Run` plumbing and the `TFrameWindow` Create/Show + message-loop bring-up faults with an access violation before presenting a window; only apps that fully customize the main window class reach a window.

- **Current:** Apps relying on the default frame-window creation and default message-loop bring-up fault before a window appears; HELLO and POPUP build but AV at launch.
- **Expected (BCC 4.52):** bcc32-built OWL runs `TApplication(title).Run()` to a live default main window and pumps messages, displaying "Hello World!"; the default-startup / `TFrameWindow` run path is a core OWL runtime contract.
- **Blocks:** The simplest class of OWL apps (default-main-window) and the gap between a curated demo and general OWL support. Blocks S6 generality.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-03** — severity high, type bug, effort L, status sharpens-parked.

- **Evidence:** `tests/owl_examples_product.rs:107-117` (HELLO, `OWLAPPS/HELLO/HELLOAPP.CPP`) and `:184-194` (POPUP) record Launch-phase KnownGap "0xC0000005 before a top-level window"; `HELLOAPP.CPP` is the one-liner `return TApplication("Hello World!").Run();`; `POPUP.CPP:206` `MainWindow = new TMainWindow(...)` (and the override at `POPUP.CPP:114,219`). The source-built `APPLICAT.CPP` default path is what faults; `wrk_owl_win64` has no `TApplication`.
- **Proposed acceptance oracle (set at Gate 1):** HELLOAPP builds, launches, shows a top-level window, responds to WM_CLOSE, and exits 0 under the `owl_examples_product` window-smoke; promoted from KnownGap(Launch) to Green.
