# MDBCC-REQ-ANVIL-00001 — `#pragma pack(push/N/pop)` silently dropped; struct packing hardwired per target

- **State:** Draft
- **Priority:** Must
- **Area:** Preprocessor
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
The preprocessor must convey `#pragma pack(push|pop|N|<empty>)` to the parser (via a reserved spliced token like `#pragma startup`, or a side-channel), and the parser must maintain a pack stack so struct layout honours the active alignment ceiling per declaration, matching bcc32 4.52.

## Rationale
The preprocessor discards every `#pragma pack` directive and the parser computes struct layout from a fixed per-target alignment ceiling, so packed regions have zero effect and `sizeof`/field offsets silently diverge from bcc32 with no diagnostic.

- **Current:** All `#pragma pack` directives are discarded; the parser byte-packs (1) on Win32 and uses natural alignment on Win64. A `#pragma pack(push,8)` … `#pragma pack(pop)` region is laid out at the fixed ceiling, so it silently disagrees with the bcc32 reference.
- **Expected (BCC 4.52):** bcc32 4.52 honours `#pragma pack(N)` / `pack(push[,N])` / `pack(pop)` / `pack()` to set the field-alignment ceiling for subsequent declarations, restoring the prior value on pop. The Win32 SDK push/pop headers (PSHPACK1/2/4/8.H, POPPACK.H) override the default per-region to give specific structs explicit packing; mdbcc cannot honour that override.
- **Blocks:** S3 real-header struct-ABI fidelity; any Win32 sample using SDK structs declared inside pack push/pop regions (TAPI/MMSYSTEM/RPC/SHLOBJ-derived layouts, currently largely not yet reachable end-to-end); sharpens the parked "bit-field/struct layout not fully bcc32-accurate" item.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PP-01** — severity critical, type missing-feature, effort L, status sharpens-parked.

- **Evidence:** `src/pp.rs:1071-1108` (`#pragma` handler acts only on `startup`; comment at `:1082` states every other pragma is ignored); `src/parser.rs:430-432` (`max_align()` returns a fixed constant — `if self.ptr_bytes >= 8 { usize::MAX } else { 1 }`, i.e. Win32 unconditionally byte-packed); oracle `wrk_oracle/bc452/BC45/INCLUDE/PSHPACK8.H:34-40`, `POPPACK.H:36`.
- **Proposed acceptance oracle (set at Gate 1):** A struct under `#pragma pack(push,1) struct S{char c; int i;}; #pragma pack(pop)` yields `sizeof == 5` and the unpacked struct yields the natural size, both matching bcc32; a `pack(8)` region restores to default on pop. Add a differential `sizeof`/offset test against the oracle's PSHPACK*/POPPACK semantics for a representative SDK struct.
