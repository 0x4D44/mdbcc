# Oracle HLD — empirical spike (2026-05-17)

Timeboxed reality check of the V7 HLD's load-bearing assumptions, run
*before* committing code to the design. Artifacts: `target/spike/` (gitignored).

## Results vs HLD assumptions

| HLD assumption | Spike result | Verdict |
|---|---|---|
| §4.3 `cl` discovery: vswhere → vcvars64 → env-inject | Works exactly as specified. VS 18 Community, MSVC 14.50.35717, `cl` resolves, 93 env vars captured | ✅ VALIDATED — implement as written |
| §4.3 known-answer probe (asserts bytes + exit 7) | exit=7 ✅; raw bytes `-7 4294967295 4294967295\r\n`. Matches HLD's `\n` expectation **only after** §4.4.3 norm | ✅ VALIDATED — probe must assert post-normalisation (HLD already says so) |
| §4.4.3 CRLF normalisation is necessary | **Every** `cl` exe emits `0d 0a`; **every** mdbcc exe emits bare `0a`. Without norm, 100% of differentials false-FAIL | ✅ VALIDATED — single most load-bearing line; correct as written |
| §4.4.1 result-via-stdout byte-equivalent post-norm (sign/width) | diff2 `-7 4294967295` byte-identical post-norm; exit codes 88/7/0 round-trip as i32 | ✅ VALIDATED — was theoretical, now proven on real binaries |
| Critique: mdbcc determinism unchecked (HashMaps in codegen) | diff1 built twice → byte-identical SHA256 | ✅ De-risked (1 sample). Keep a cheap compile-twice property test; not a blocker |
| §2/§10/§8: no Borland here; bcc availability = top risk; O3 deferred to v3 (manual, "may stay unbuilt") | Confirmed: no Borland on box (PATH `bcc.exe` is **mdbcc itself**). **BUT** outbound network fully reachable: archive.org / altd.embarcadero.com / www.embarcadero.com / github.com all TCP443 OK, archive.org HTTP 200 | ⚠️ **CHANGED** — O3's presumed hard blocker is likely solvable now; O3 reachable far sooner than "v3 / Arthur-manual / maybe never" |
| (not in HLD) PATH hygiene | A stale `c:\apps\bcc.exe` (a copy of mdbcc) is on PATH | 🆕 Hazard — harness must invoke the cargo-built artifact path explicitly, **never** `bcc` by name |

## Strategic read (answers the critique's open question)

- **O2 mechanism is cheap and works end-to-end today.** No technical reason
  not to build it. CRLF norm is the only subtlety and it is nailed.
- **The spike found zero mdbcc bugs via differential** (diff1/diff2 both
  agreed). Doesn't prove O2 worthless, but consistent with the critique:
  O1's 146 hand-oracle e2e tests already cover mdbcc's narrow subset.
  O2's real value is **(a) regression net as the subset grows** and
  **(b) cheap corpus authoring** (MSVC computes the oracle instead of
  hand-computation) — *not* bug-finding on today's subset.
- **O3 is the oracle that tests the actual project goal** (Borland-dialect
  fidelity). The spike just removed its presumed blocker. This is the
  priority-inversion the critique warned about, now actionable.

## Conclusion

The V7 design is empirically sound — every mechanism assumption held.
The one strategically significant change is external, not in the design:
**network works, so O3 is no longer "maybe never".** Decision for Arthur:
build O2 v1 as designed, or pivot to acquire a real Borland compiler and
bring O3 forward (O2's marginal signal over O1 on today's subset is the
weakest link; O3 is where the project's stated value lives).

## Acquisition (2026-05-17) — bcc32 5.5.1 secured (HLD §9 / O3)

Arthur chose "acquire Borland first". Done, sandbox-safe:

- Precondition applied: `wrk_tools/` + `wrk_corpus/` added to `.gitignore`
  (`git check-ignore` exit 0). Copyrighted binaries can't be committed.
- Genuine Borland C++ **5.5.1** command-line toolchain extracted to
  `wrk_tools\BCC55\` — `Bin\bcc32.exe` (PE version resource read
  statically: FileVersion 5.5, Company "Borland", "Borland C/C++
  Compiler"), plus `ilink32/cpp32/brc32/brcc32` + 1082 headers + 191 libs
  (`stdio.h`, `windows.h`, `cw32.lib`, `import32.lib` all present).
  1435 files, 50.8 MB.
- Source: Internet Archive item `BCC55PubliclyAvailableBorlandCCompiler5.5`
  — a **pre-extracted tree in a ZIP** (no installer to run). Acquired via
  download + managed `Expand-Archive` only.
  - zip  sha256 `8944076EB6EC500412605314B2EB5BA3458D2EE2FF15331A4122E8B3B626F7CC`
  - bcc32 sha256 `E7F7853E8C71B120839FAB6505516799EC0D4BD9AE0797DCF00A1A6656AB1E5B`
- Canonical Embarcadero `altd` CDN URLs are dead (404). bcc64 (modern
  Win64) is registration-form-gated — not scriptable; deferred. bcc32-5.5
  is exactly the HLD §3 *acceptance* arm (`bcc32 -c`); Win32 so
  behavioural use needs pointer-size filtering (§4.5/§10).

### Blocking boundary: executing bcc32 is sandbox-gated

The sandbox **correctly blocks executing freshly-downloaded binaries**
(`EPERM uv_spawn` when Start-Process'ing the installer; bcc32.exe is the
same class). Acquisition is complete and safe; **running** bcc32 (for
`bcc32 -c` acceptance or behavioural O3) requires either
`dangerouslyDisableSandbox` on those specific compile steps, or a trusted
manual run by Arthur. This is a security-boundary decision for Arthur —
not taken unilaterally.
