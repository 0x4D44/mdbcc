# MDBCC-REQ-ANVIL-00068 — OWL message crackers truncate 64-bit HWND/HANDLE parameters to 32-bit `uint`

- **State:** Draft
- **Priority:** Must
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Crackers that deliver an HWND/HANDLE to a handler (WM_ACTIVATE, WM_MDIACTIVATE, WM_PARENTNOTIFY, WM_MENUCHAR, CTL_COLOR and peers) must pass the handle at full pointer width on Win64, not truncated through a 32-bit `uint` parameter; the corresponding handler signatures must be widened to match so the PMF type and member agree.

## Rationale
Cracker PMFs in `DISPATCH.CPP` are declared with 32-bit `uint` parameters, so a pointer-width `WPARAM`/`LPARAM` carrying an HWND/HANDLE is truncated to its low 32 bits before the OWL `EvXxx` handler sees it. The WM_COMMAND path was patched for this; the `DISPATCH.CPP` cracker family was not.

- **Current:** An HWND/HANDLE in `wParam`/`lParam` is passed into a `uint` PMF slot and truncated to its low 32 bits before reaching the handler.
- **Expected (BCC 4.52):** On Win64 a handle passed to an `EvXxx` handler must arrive full-width; the 16-bit/bcc32 crackers used `uint` only because HWND fit there, so the Win64 port must widen the cracker PMF parameter types and the handler signatures to a pointer-width handle type.
- **Blocks:** Correct activation/MDI/parent-notify handling in any OWL app that uses the other-window HWND; latent wrong-behaviour on the Win64 product path. Blocks S6/S7 for MDI and multi-window samples.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-02** — severity high, type bug, effort M, status new.

- **Evidence:** `wrk_owl_win64/DISPATCH.CPP:292-304` (`v_Activate_Dispatch`), `:306-318` (`v_MdiActivate_Dispatch`, two HWNDs), `:320-331` (`I32_MenuChar_Dispatch`), `:333-348` (`v_ParentNotify_Dispatch`); PMF type `void(GENERIC::*)(uint,uint,uint)` at `DISPATCH.H:316-320` vs real handler `EvActivate(uint,bool,HWND)` at `window.h:670-672`; `uint` is 32-bit (`OSL/DEFS.H:79`), HWND is a 64-bit `DECLARE_HANDLE` (`WINDEF.H:190`); fixed counterpart `WINDOW.CPP:822-826`; peer instance CTL_COLOR at `WINDOW.CPP:1226`.
- **Proposed acceptance oracle (set at Gate 1):** A handler that records the HWND it received for WM_ACTIVATE/WM_MDIACTIVATE asserts the value equals the full 64-bit handle the message carried; an MDI or activation-sensitive OWL sample behaves correctly.
