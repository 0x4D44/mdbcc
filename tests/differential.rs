//! Differential oracles (V8 §8 v1): O2 = MSVC `cl`, O3 = Borland `bcc32
//! 5.5.1` (acceptance + Win32 behavioural), plus the dialect parse-smoke
//! tripwire and an mdbcc determinism guard.
//!
//! O1 (`tests/end_to_end.rs`) is **untouched and authoritative**; these
//! only add signal. Every breach of a §4.3 health guard **fails the test
//! process** (an oracle-health halt, not an mdbcc verdict). External
//! oracles self-skip loudly when their toolchain is absent; "zero external
//! oracles active" is itself a halt (§6).

#![cfg(windows)]

mod support;

use support::*;

/// Accumulated counts for one differential arm (V8 §4.3).
#[derive(Default)]
struct Acc {
    name: String,
    nonskip: usize,
    compared: usize,
    passed: usize,
    failures: Vec<(String, String)>,
    build_launch_fail: usize,
    excluded: Vec<(String, String)>,
    warns: Vec<String>,
}

impl Acc {
    fn new(name: &str) -> Self {
        Acc {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn record(&mut self, file: &str, v: Verdict) {
        match v {
            Verdict::Pass => {
                self.compared += 1;
                self.passed += 1;
            }
            Verdict::Fail(r) => {
                self.compared += 1;
                self.failures.push((file.to_string(), r));
            }
            Verdict::Exclude(r) => {
                if r.contains("reference build/launch failed") {
                    self.build_launch_fail += 1;
                }
                self.excluded.push((file.to_string(), r));
            }
        }
    }

    fn fmt_list(items: &[(String, String)]) -> String {
        items
            .iter()
            .map(|(f, r)| format!("  - {f}: {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Evaluate §4.3 health guards. **Every breach panics** (halts the
    /// loop). `WARN`/`STOP` are severity labels only — all halt. A
    /// sub-threshold set of failures is a normal, actionable mdbcc red
    /// (also a panic — it must fail `cargo test`).
    fn finish(self) {
        for w in &self.warns {
            eprintln!("WARN: {w}");
        }
        if !self.excluded.is_empty() {
            eprintln!(
                "[{}] {} excluded (not agreement, not a red):\n{}",
                self.name,
                self.excluded.len(),
                Self::fmt_list(&self.excluded)
            );
        }
        if self.compared == 0 {
            panic!(
                "WARN: {} compared nothing — not green (oracle-health halt; \
                 O1 remains authoritative)",
                self.name
            );
        }
        if self.build_launch_fail >= 5 && self.build_launch_fail * 4 >= self.nonskip {
            panic!(
                "WARN: {} toolchain broken — {}/{} non-skip files failed to \
                 build/launch (oracle-health halt)",
                self.name, self.build_launch_fail, self.nonskip
            );
        }
        if self.failures.len() >= 5 && self.failures.len() * 4 >= self.compared {
            panic!(
                "STOP: {} broad-divergence — triage required ({}/{} compared \
                 FAILed). Auto-attributes nothing: NOT green, NOT a clean \
                 mdbcc red, NOT a reference exoneration. O1 remains the \
                 authoritative gate.\nfailures:\n{}",
                self.name,
                self.failures.len(),
                self.compared,
                Self::fmt_list(&self.failures)
            );
        }
        if !self.failures.is_empty() {
            panic!(
                "{} FAIL — {} actionable mdbcc red(s):\n{}",
                self.name,
                self.failures.len(),
                Self::fmt_list(&self.failures)
            );
        }
        println!(
            "[{}] OK — {}/{} compared passed, {} excluded.",
            self.name,
            self.passed,
            self.compared,
            self.excluded.len()
        );
    }
}

// ---------------------------------------------------------------------------
// O2 — MSVC `cl` behavioural differential over tests/corpus/portable
// ---------------------------------------------------------------------------

#[test]
fn o2_msvc_differential() {
    if !o2_active() {
        println!("[O2] SKIP: cl not found or environment unusable (self-skip).");
        return;
    }
    let mut acc = Acc::new("O2 (MSVC cl)");
    for (path, src) in corpus_files("portable") {
        let file = label(&path);
        if let Skip::Full(why) = parse_skip(&src) {
            acc.warns.push(format!("{file} skipped: {why}"));
            continue;
        }
        acc.nonskip += 1;
        let lang = parse_lang(&src);
        if msvc_ref_o2_unstable(&src, lang) {
            acc.warns.push(format!(
                "{file} reference-unstable (/Od vs /O2) — hand-curate"
            ));
        }
        let md = mdbcc_run(&src);
        let rf = msvc_ref(&src, lang);
        acc.record(&file, compare(&md, &rf));
    }
    acc.finish();
}

// ---------------------------------------------------------------------------
// O3 — Borland bcc32 5.5.1: acceptance (portable + dialect)
// ---------------------------------------------------------------------------

#[test]
fn o3_bcc32_acceptance() {
    if !o3_active() {
        println!("[O3-accept] SKIP: bcc32 not present/usable (self-skip).");
        return;
    }
    let mut acc = Acc::new("O3 acceptance (bcc32 -c)");
    for sub in ["portable", "dialect"] {
        for (path, src) in corpus_files(sub) {
            let file = label(&path);
            if let Skip::Full(why) = parse_skip(&src) {
                acc.warns.push(format!("{file} skipped: {why}"));
                continue;
            }
            acc.nonskip += 1;
            // mdbcc must compile it (else this file is not a fair
            // acceptance comparison — it is an mdbcc red O1/smoke owns).
            if mdbcc_compile(&src).is_err() {
                acc.record(
                    &file,
                    Verdict::Exclude("mdbcc does not compile it (owned elsewhere)".into()),
                );
                continue;
            }
            match bcc32_accept(&src, parse_lang(&src)) {
                Ok(()) => acc.record(&file, Verdict::Pass),
                Err(e) => acc.record(
                    &file,
                    // Authentic Borland rejects code mdbcc claims to
                    // support ⇒ a real, actionable dialect red.
                    Verdict::Fail(format!("bcc32 rejected it: {e}")),
                ),
            }
        }
    }
    acc.finish();
}

// ---------------------------------------------------------------------------
// O3 — Borland bcc32 5.5.1: Win32 behavioural over portable (ptr-size filtered)
// ---------------------------------------------------------------------------

#[test]
fn o3_bcc32_behavioural() {
    if !o3_active() {
        println!("[O3-behave] SKIP: bcc32 not present/usable (self-skip).");
        return;
    }
    let mut acc = Acc::new("O3 behavioural (bcc32 Win32)");
    for (path, src) in corpus_files("portable") {
        let file = label(&path);
        match parse_skip(&src) {
            Skip::Full(why) => {
                acc.warns.push(format!("{file} skipped: {why}"));
                continue;
            }
            Skip::Bcc32Behaviour(why) => {
                acc.warns
                    .push(format!("{file} skipped (bcc32 ptr-size): {why}"));
                continue;
            }
            Skip::None => {}
        }
        acc.nonskip += 1;
        let md = mdbcc_run(&src);
        let rf = bcc32_ref(&src, parse_lang(&src));
        acc.record(&file, compare(&md, &rf));
    }
    acc.finish();
}

// ---------------------------------------------------------------------------
// Dialect parse-smoke tripwire (V8 §4.1): mdbcc must not error/panic.
// Green is NOT evidence the construct is supported (mdbcc silently drops
// unrecognised constructs) — it is a crash/parser-error tripwire only.
// ---------------------------------------------------------------------------

#[test]
fn dialect_parse_smoke() {
    let files = corpus_files("dialect");
    assert!(!files.is_empty(), "dialect corpus is empty");
    let mut reds = Vec::new();
    for (path, src) in files {
        let file = label(&path);
        if let Err(e) = mdbcc_compile(&src) {
            reds.push(format!("  - {file}: {e}"));
        }
    }
    if !reds.is_empty() {
        panic!(
            "dialect parse-smoke tripwire FAILED ({} file(s) error/panic in \
             mdbcc):\n{}",
            reds.len(),
            reds.join("\n")
        );
    }
    println!("[dialect-smoke] OK (tripwire only — not a support claim).");
}

// ---------------------------------------------------------------------------
// mdbcc determinism guard (V8 §4.6 / §6): same source ⇒ identical bytes.
// Cheap tripwire against accidental nondeterministic emission (codegen
// uses HashMaps). Not an oracle.
// ---------------------------------------------------------------------------

#[test]
fn mdbcc_determinism() {
    let files = corpus_files("portable");
    assert!(!files.is_empty(), "portable corpus is empty");
    for (path, src) in files {
        // Compile failure here is owned by O1/O2/O3, not this guard.
        if let (Ok(x), Ok(y)) = (mdbcc_compile(&src), mdbcc_compile(&src)) {
            assert!(
                x == y,
                "mdbcc nondeterministic on {} ({} vs {} bytes)",
                label(&path),
                x.len(),
                y.len()
            );
        }
    }
    println!("[determinism] OK — mdbcc byte-stable across recompiles.");
}

// ---------------------------------------------------------------------------
// Coverage summary + the §6 "zero external oracles active" halt.
// ---------------------------------------------------------------------------

#[test]
fn oracle_coverage_summary() {
    let o2 = o2_active();
    let o3 = o3_active();
    let o2s = if o2 {
        "ACTIVE".to_string()
    } else {
        "SKIP(cl unusable)".to_string()
    };
    let o3s = if o3 {
        "ACTIVE (bcc32 5.5.1: accept + Win32 behave)".to_string()
    } else {
        "SKIP(bcc32 absent)".to_string()
    };
    println!(
        "oracles: O1 ACTIVE (authoritative) | O2 {o2s} | O3 {o3s} | \
         dialect-smoke (tripwire) | determinism-guard"
    );
    assert!(
        o2 || o3,
        "zero external differential oracles active — loud halt (O1 stays \
         authoritative but the differential signal is gone; not green)"
    );
}
