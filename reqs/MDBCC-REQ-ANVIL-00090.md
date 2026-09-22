# MDBCC-REQ-ANVIL-00090 — i386 runtime can go fully unverified on incapable/WOW64-refusing hosts while the suite stays green

- **State:** Draft
- **Priority:** Should
- **Area:** Testing & oracles
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Treat "i386 cannot be executed on this host" as a single explicit, loud oracle-health state (detected once, reported once) and gate it so a host that *claims* i386 support but runs zero i386 programs fails; retain the always-on i386 byte-identity stripe as the documented sole guarantee when execution is impossible.

## Rationale
On an arm64 host, a 64-bit-only Windows SKU, or any box where WOW64 refuses the 32-bit image, every i386 *runtime* assertion degrades to a bare `eprintln` non-failure, and the i386 differential self-skips — so the i386 backend (a live S2/S6 frontier) can be entirely runtime-unverified with CI green.

- **Current:** Spawn failure yields a non-counted skip; nothing distinguishes "host genuinely cannot run i386" from "host could but ran zero i386 programs." The always-on byte-identity stripe (`tests/o1_x86_byte_identity.rs`, non-vacuity guard at `:316`) still pins emitted i386 PE bytes regardless of WOW64.
- **Expected (BCC 4.52):** A live i386 frontier must not be silently unexercised at runtime; the inability to run i386 must itself be a loud, countable, gated health state, mirroring the existing `o2_active`/`o3_active` "zero oracles active is a halt" idiom.
- **Blocks:** S2/S6 i386 correctness confidence.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **TST-01** — severity medium, type testing, effort M, status sharpens-parked.

- **Evidence:** `C:\language\mdbcc\tests\i386_run.rs:73,114` print `SKIP ... spawn failed (WOW64 refused image?)` and return `None`, which the caller treats as non-failure; `C:\language\mdbcc\tests\abi_torture.rs:440` `let Some(code) = run_exit(...) else { continue; }` silently skips the i386 arm; the O12 differential self-skips when BC4.52 is absent (`quality_map.rs:92-93`); the always-on differential (`differential.rs`) exercises only Win64 and its "zero oracles active is a halt" gate (`differential.rs:306`) covers only the O2/O3 Win64 differential, not i386 runtime capability.
- **Proposed acceptance oracle (set at Gate 1):** On a WOW64-capable host, an injected spawn-failure fails the i386 suite instead of skipping; on a genuinely i386-incapable host exactly one health line is emitted and the byte-identity stripe still runs and gates.
