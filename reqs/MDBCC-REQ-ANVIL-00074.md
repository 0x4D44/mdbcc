# MDBCC-REQ-ANVIL-00074 — OWL message-cache this-adjustment delta computed via 32-bit-truncating pointer cast

- **State:** Draft
- **Priority:** Could
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Compute the OWL message-cache `this`-adjustment delta as a pointer difference, not a difference of `int`-truncated pointers, eliminating the latent Win64 truncation idiom.

## Rationale
The cached `this`-adjustment delta is computed as the difference of two pointers cast to 32-bit `int`. The result is correct today because the subobject offset always fits in an `int`, but it is a fragile pointer-truncation idiom on a known-truncation-sensitive line that the overlay audited and fixed elsewhere.

- **Current:** The delta is the difference of two `int`-truncated pointers; correctness relies on the offset magnitude fitting an `int` (which it always does), so it works today but reads as a latent truncation idiom on the Win64 path.
- **Expected (BCC 4.52):** The delta should be computed as a full-width pointer difference — `(int)((char*)eventInfo.Object - (char*)this)` — avoiding any pointer truncation.
- **Blocks:** None (defence-in-depth for the dispatch path implicated in OWL-01/OWL-02; not a confirmed live failure today).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-08** — severity low, type tech-debt, effort S, status new.

- **Evidence:** `wrk_owl_win64/WINDOW.CPP:856` `...Set(..., int(eventInfo.Object) - int(this))`, field `int Delta;` at `WINDOW.CPP:754`, default `cacheEnabled=true` `:770`, `OWL_RTTI_MSGCACHE` `:37`, re-applied at `:847` `(GENERIC*)(((char*)this) + msgCache[key].Delta)`; adjacent WM_COMMAND truncation already patched at `:822-826`.
- **Proposed acceptance oracle (set at Gate 1):** Line patched to a `char*`-difference with an intent comment; a build/run of the cached-dispatch fast path (a sample that hits `msgCache` repeatedly) behaves identically, with no behavioural regression in BUTTON/INSTANCE smoke.
