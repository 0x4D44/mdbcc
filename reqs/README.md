# Requirements — `reqs/` directory ledger

**Purpose.** A requirement is a **living spec**: a durable, attributed
statement of required behaviour plus a re-runnable **oracle** that proves it.
One markdown file per requirement under `reqs/`, the filename == the
requirement ID; deltic assembles the ledger in memory by globbing `reqs/*.md`
and surfaces it as the F2 Repos→Reqs pill. There is **no master table** by
design, and **no `REQS.md` — never create one.** This mirrors a `bugs/`
directory ledger; the difference is that a requirement never auto-closes —
once `Satisfied` it can flip to `Violated` and back, so the ledger answers
*"what must this system always do, and is it still doing it?"*.

> **This repo's bug ledger is the flat `BUGS.md` file** (not a `bugs/`
> directory). `Violated-by` refs therefore point at `BUGS.md` IDs
> (`B-NN` / `F-NN` / the historical `MDBCC-NN`), resolved by hand rather than
> against a sibling `bugs/` directory.

**ID grammar.** `PREFIX-REQ-HOST-NNNNN`.
- **PREFIX** — this repo's acronym: `MDBCC`.
- **REQ** — the type token (a bug ledger uses `BUG`; `REQ` is reserved for this
  ledger). deltic never inspects the token — both ledgers share one ID parser.
- **HOST** — the minting machine's hostname, uppercased with every non
  `[A-Z0-9]` char stripped, **not truncated** (e.g. `ANVIL`).
- **NNNNN** — a per-host sequence, zero-padded to at least 5 digits.
- Legacy `PREFIX-NNNNN` ids (pre-conversion) remain valid, verbatim, forever.

**Per-host allocation.** To raise a requirement: derive HOST at runtime
(`echo %COMPUTERNAME%` on Windows, `hostname` on Linux/WSL), list the existing
`MDBCC-REQ-<HOST>-*` files, take `max(NNNNN)+1`, and commit that one new file.
No central allocator, no lock.

**Merge safety (R-SAMEHOST).** The filename **stem is the identity**. Two
actors sharing a HOST token (worktrees on one box, a Win+WSL pair with the same
hostname) can mint the same id from stale views — this surfaces **loudly** as
an add/add conflict at integration, never a silent collision. The resolver
renumbers. If a file's H1 id disagrees with its filename, deltic keys the
record by the **filename** and carries a "differs from filename" warning.

**States & transitions.**

```
Draft ──► Accepted ──► Implemented ──► Satisfied ⇄ Violated
                            │                          ▲
                            └──────────────────────────┘   (Implemented can be noticed Violated)
any state ──► Retired (terminal)
```

| State | Meaning |
|---|---|
| **Draft** | Proposed, under discussion. |
| **Accepted** | Binding, not yet met (outstanding). |
| **Implemented** | Code is present, but the oracle is missing/incomplete — regression-blind. |
| **Satisfied** | Code **and** a complete oracle (automated, or a documented manual check). |
| **Violated** | Built then breached — the alarm. Reachable from `Satisfied` *or* directly from `Implemented`. |
| **Retired** | Withdrawn or superseded (terminal). |

State is a **field inside the file** (`- **State:** …`) — never rename a file
to change its state. Transitions are append-only and dated in the
`State history:` line. deltic only *classifies* the declared state (a
case-insensitive contains-scan, `retired → violated → satisfied → implemented
→ accepted → draft`); it never derives or enforces a transition and never
mutates a file. An unrecognised state word classifies as `Other`.

**Field set.** Modeled fields are the `- **Field:**` bullets **above the first
`## ` heading**; everything from the first level-2 heading on is free prose.

| Label | Meaning |
|---|---|
| `State` | One of the six states above. |
| `Priority` | MoSCoW: `Must` / `Should` / `Could` (unknown/blank → `—`). |
| `Area` | Free text (the module/feature the requirement governs). |
| `Raised` | First-raised date (else the first `State history` date). |
| `Implemented-by` | req→code refs — see traceability. |
| `Satisfied-by` | req→oracle refs — see traceability. |
| `Violated-by` | req→bug refs (`BUGS.md` IDs) — see traceability. |
| `Flow` | `light` / `heavy` — which build flow the `/loop` runner uses (blank/unknown → `—`, not loop-routable). |
| `Claimed-by` | The loop's in-flight marker: `<agent>@<host> (<when>)` while a runner holds it, else `—`. |
| `State history` | Dated, append-only transitions. |

**Traceability (three labelled lines).** Multiple refs are comma-separated on
the one line; an empty value or `—` means "none yet".

- `Implemented-by:` — **req→code**. Free-text path/symbol refs, displayed not
  resolved. Their presence is what the Implemented→Satisfied semantics hinge on.
- `Satisfied-by:` — **req→oracle**. Free-text test path / command refs. Its
  **non-emptiness is the honesty check's signal**. When automation is genuinely
  impractical, name a documented re-runnable manual check prefixed `manual:`.
  deltic treats any non-empty `Satisfied-by` as "oracle present" and never
  executes anything.
- `Violated-by:` — **req→bug**. `BUGS.md` ledger IDs, resolved by hand in this
  repo (the flat ledger is not a `bugs/` directory deltic auto-resolves).

`Implemented-by` / `Satisfied-by` are free text and are **never** shape-checked.

**Honesty rule + two-eyes process.** A `Satisfied` claim is the model's whole
point — and the exact lie it must prevent. deltic **mechanically flags** a
requirement marked `Satisfied` with an **empty `Satisfied-by`** (no oracle).
deltic only checks that an oracle is *named*, not that it passes, so the human
gate on truth is the **two-eyes rule**: a requirement moves `Implemented →
Satisfied` only after a **second pair of eyes** confirms the named oracle
genuinely exists and passes.

**File format.** Each `reqs/<ID>.md`:

```markdown
# MDBCC-REQ-ANVIL-00001 — <short imperative title>

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
<what the system must do, as a durable behavioural spec — not a task>

## Rationale
<why it matters / who it's for>
```

**The `/loop` runner & the claim protocol.** The reqs ledger doubles as the
**work queue** for the `/loop` runner skill. The human gates *batches*, not
every diff:

- **Gate 1 (human, batch triage).** Review `Draft` reqs; set `Priority`, `Flow`,
  and the acceptance oracle (`Satisfied-by` the build is proven against), then
  move to `Accepted` (or `Retired` for one-shot tasks that aren't durable
  requirements). This is the cull.
- **The loop drains *ready* reqs** — `deltic reqs --ready` = `Accepted`, a
  routable `Flow` (not `—`), and **unclaimed**. Per req:
  - **`Flow: light`** → the runner **claims** it, builds to the `Satisfied-by`
    oracle on its own worktree branch, then moves it to `Implemented` and
    **clears `Claimed-by`**. It never pushes, never flips to `Satisfied`.
  - **`Flow: heavy`** → the runner **reports it to the human** and skips.
- **Gate 2 (human, batch, two-eyes).** A requirement moves `Implemented →
  Satisfied` only after a **second pair of eyes** re-runs the named oracle and
  confirms it passes; the human then integrates.

deltic only *reads, classifies, and surfaces* the ledger — **the skills are the
only writers of req files** (deltic never mutates one).

---

## Provenance — initial batch

The first 113 requirements (`MDBCC-REQ-ANVIL-00001`–`00113`) were captured on
2026-06-21 from
`wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md`
(the 19-dimension gap analysis: 107 subsystem requirements + 6 cross-seam
additions). All are `Draft` with empty traceability, awaiting Gate 1 triage.
Each file's `## Source` section cross-references its origin item ID
(`PP-01`, `EH-02`, `GAP-01`, …) and carries the proposed acceptance oracle to
seed `Satisfied-by` at the gate. `Priority`/`Flow` are proposals
(critical/high → Must, medium → Should, low → Could; S/M → light, L/XL → heavy).
