# MDBCC-REQ-ANVIL-00014 — Anonymous aggregate member dropped on the declarator parse path

- **State:** Draft
- **Priority:** Could
- **Area:** Parser — C language
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Make the declarator-path anonymous-aggregate case (`src/parser.rs:2592-2598`) keep the member as a `$anon.N` field exactly as the bare-type path does, so layout is preserved regardless of parse route.

## Rationale
Whether an anonymous `struct`/`union` member preserves layout depends on the parse route: the bare-type path keeps it as `$anon.N`, but the declarator path (reached when a non-`;` token such as a trailing cv-qualifier follows `}`) drops it entirely, contributing no field.

- **Current:** An anonymous aggregate member flowing through the declarator path contributes no field, so the enclosing record's size and the offsets of following members are wrong; the same construct via the bare-type path is laid out correctly. In-scope OWL `TMessage`-shaped structs use the bare `union {...};` form and hit the correct path, so this is a latent/defensive inconsistency rather than an active miscompile on the current corpus.
- **Expected (BCC 4.52):** bcc32 lays out the anonymous aggregate's storage in the enclosing record regardless of declarator syntax; the two parser paths must agree.
- **Blocks:** Byte-accurate layout of records with anonymous aggregate members on any parse route; struct byte-identity oracles.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSC-05** — severity low, type incomplete, effort S, status new.

- **Evidence:** bare-type path `src/parser.rs:2513-2526` (keeps `$anon.N`); declarator path `src/parser.rs:2588-2598` (advances over `;` and breaks, pushing no field).
- **Proposed acceptance oracle (set at Gate 1):** A test where an anonymous union member is parsed via the declarator path (e.g. with a trailing cv-qualifier routing through `declarator()`) asserts `sizeof` the enclosing record and the offset of a following named member match the bare-type-path result.
