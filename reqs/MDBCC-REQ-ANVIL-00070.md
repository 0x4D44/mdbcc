# MDBCC-REQ-ANVIL-00070 — OWL control-subclass constructor forwarding (GROUPBOX, EDIT) fails to reach clean codegen+link

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
First classify the actual GROUPBOX/EDIT failure (the cause is not yet proven); then make constructor overload resolution and codegen handle OWL control base-constructor forwarding (far-qualified `char*` params, trailing defaulted `TModule*` args) so the stock control-subclass examples compile.

## Rationale
Stock OWL control subclasses (GROUPBOX, EDIT) do not reach a clean codegen+link on the product path, so the examples never link. The named "constructor overload-resolution" cause is unverified — the KnownGap reason is a human annotation, the matrix test never asserts the phase, and a true overload failure would more plausibly classify as Parse; both files also exercise BIDS `string`, fstream, validators/dialogs, and response-table macros, any of which is a candidate culprit.

- **Current:** Compiling a stock OWL control subclass whose ctor forwards to a multi-parameter base control constructor (far-qualified `char*`, trailing defaulted `TModule*`) fails at the codegen phase and the example never links.
- **Expected (BCC 4.52):** bcc32 compiles these unmodified stock BC4.52 examples — resolving the `TGroupBox`/`TEdit` constructor overload from the forwarded argument list and emitting the base-ctor call.
- **Blocks:** All OWL control-subclass examples that forward to base control ctors (the common OWL idiom). Blocks S6 generality.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-04** — severity high, type bug, effort L, status sharpens-parked.

- **Evidence:** `tests/owl_examples_product.rs:118-139` (GROUPBOX `GROUPBXX.CPP`, EDIT `EDITX.CPP` as Codegen-phase KnownGap); `GROUPBXX.CPP:27-33` (derived ctor forwards `TGroupBox(parent,id,text,X,Y,W,H,module)` with `const char far*` text); `src/codegen.rs:503` (`classify_build_error` routes "no matching overload"/"ambiguous" to Parse, yet these bucketed as Codegen); parked at `scratchpad.md:13-14` and backlog `tests/quality_map.rs:203`.
- **Proposed acceptance oracle (set at Gate 1):** GROUPBOX and EDIT examples reach codegen+link clean (promoted past the Codegen KnownGap), backed by a focused test exercising a derived-control ctor forwarding to a base ctor with a far `char*` + defaulted `TModule*` (once classification confirms that is the blocker).
