//! G6 — RAILC.RC end-to-end oracle: compile the real-world Borland
//! resource script and compare against the BC4.5-era golden `.res`.
//!
//! The oracle is `wrk_oracle/railc_golden/railc.res` (byte-identical to
//! the `railc.res` Borland's brc produced from
//! `C:\language\railc\RESOURCE\RAILC.RC` in the original build). Where
//! the golden and MSDN disagree, the golden wins — it is the spec.
//!
//! The source `.rc` lives in the (read-only) railc tree, outside this
//! repo; the test skips gracefully when that tree is absent (CI without
//! the sandbox corpus), mirroring the `Option<Brc>` pattern in
//! `tests/rc_res.rs`.
//!
//! Assertion ladder (ratcheted as the increments landed):
//! 1. `rc::compile_file` succeeds (preprocessor + lexer + parser).
//! 2. Record inventory matches: count, and per-record (type, name,
//!    language, memory flags, data size) — readable diff on mismatch.
//! 3. Per-record payload bytes match.
//! 4. The whole `.res` byte stream is identical (header padding rules
//!    and record framing included).
//!
//! Salvaged from the `wf_5a36b7a6-b30-2` worktree's parked mdrc build-out
//! (MDBCC-04). main's committed W5/W6 RC compiler supersedes that build-out
//! at the source level, but it lacked this byte-identical golden oracle —
//! the one artifact worth keeping. Ported verbatim except the `compile_file`
//! defines argument, which on main is a `&HashMap<String, String>`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mdbcc::rc;

/// `C:\language\railc\RESOURCE\RAILC.RC` — the real-world corpus root.
/// Returns `None` (test skips) when the railc tree is not present.
fn railc_rc_path() -> Option<PathBuf> {
    let p = Path::new(r"C:\language\railc\RESOURCE\RAILC.RC");
    if p.exists() { Some(p.to_path_buf()) } else { None }
}

/// The golden `.res` from `wrk_oracle/` — checked next to the manifest
/// first (the main checkout), then at the canonical sandbox path (so
/// worktree builds, where `wrk_oracle/` is untracked, still find it).
/// `None` (test skips) when neither exists.
fn golden_res_bytes() -> Option<Vec<u8>> {
    let candidates = [
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("wrk_oracle")
            .join("railc_golden")
            .join("railc.res"),
        PathBuf::from(r"C:\language\mdbcc\wrk_oracle\railc_golden\railc.res"),
    ];
    candidates.iter().find_map(|p| std::fs::read(p).ok())
}

// ---------------------------------------------------------------------------
// Minimal .res reader (the inverse of src/rc/res.rs::write_record) —
// the test's own decoder so writer bugs can't hide behind shared code.
// ---------------------------------------------------------------------------

/// Type or name field of a `.res` record header.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TypeOrName {
    Ord(u16),
    Name(String),
}

impl std::fmt::Display for TypeOrName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeOrName::Ord(o) => write!(f, "#{o}"),
            TypeOrName::Name(s) => write!(f, "{s:?}"),
        }
    }
}

/// One decoded `.res` record (header fields + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResRecord {
    rtype: TypeOrName,
    name: TypeOrName,
    mem: u16,
    lang: u16,
    data: Vec<u8>,
}

fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Decode an `FFFF + ord` or UTF-16LE NUL string field; returns the
/// value and the byte length consumed.
fn read_type_or_name(b: &[u8], off: usize) -> (TypeOrName, usize) {
    if read_u16(b, off) == 0xFFFF {
        (TypeOrName::Ord(read_u16(b, off + 2)), 4)
    } else {
        let mut units = Vec::new();
        let mut i = off;
        loop {
            let u = read_u16(b, i);
            i += 2;
            if u == 0 {
                break;
            }
            units.push(u);
        }
        (TypeOrName::Name(String::from_utf16_lossy(&units)), i - off)
    }
}

/// Split a `.res` byte stream into records, dropping the leading 32-byte
/// null sentinel (asserted present).
fn parse_res(bytes: &[u8]) -> Vec<ResRecord> {
    let mut records = Vec::new();
    let mut off = 0usize;
    while off + 8 <= bytes.len() {
        let data_size = read_u32(bytes, off) as usize;
        let header_size = read_u32(bytes, off + 8 - 8 + 4) as usize;
        let mut h = off + 8;
        let (rtype, n) = read_type_or_name(bytes, h);
        h += n;
        let (name, n) = read_type_or_name(bytes, h);
        h += n;
        // Pad type+name to DWORD within the header.
        while !(h - off).is_multiple_of(4) {
            h += 1;
        }
        let _data_version = read_u32(bytes, h);
        let mem = read_u16(bytes, h + 4);
        let lang = read_u16(bytes, h + 6);
        assert_eq!(h + 16 - off, header_size, "header size mismatch at offset {off}");
        let data_start = off + header_size;
        let data = bytes[data_start..data_start + data_size].to_vec();
        // Advance past data + DWORD pad.
        off = data_start + data_size;
        while !off.is_multiple_of(4) {
            off += 1;
        }
        records.push(ResRecord { rtype, name, mem, lang, data });
    }
    assert_eq!(off, bytes.len(), "trailing bytes after last record");
    // First record must be the null sentinel.
    let first = records.remove(0);
    assert_eq!(first.rtype, TypeOrName::Ord(0), "missing null sentinel");
    assert_eq!(first.name, TypeOrName::Ord(0), "missing null sentinel");
    assert!(first.data.is_empty(), "null sentinel carries data");
    records
}

/// Render a record for diff output: `type name lang mem dsize`.
fn describe(r: &ResRecord) -> String {
    format!(
        "type={} name={} lang={:#06x} mem={:#06x} dsize={}",
        r.rtype,
        r.name,
        r.lang,
        r.mem,
        r.data.len()
    )
}

/// First differing byte offset between two slices, for payload diffs.
fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    if a == b {
        return None;
    }
    Some(a.iter().zip(b.iter()).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len())))
}

// ---------------------------------------------------------------------------
// THE acceptance test for the rc compiler (GAP-LIST item 9).
// ---------------------------------------------------------------------------

#[test]
fn railc_rc_matches_golden_res() {
    let Some(rc_path) = railc_rc_path() else {
        eprintln!("SKIP: C:\\language\\railc\\RESOURCE\\RAILC.RC not present");
        return;
    };
    let Some(golden) = golden_res_bytes() else {
        eprintln!("SKIP: wrk_oracle\\railc_golden\\railc.res not present");
        return;
    };

    // Increment 1: the full pipeline (preprocess → lex → parse) succeeds.
    // No -D defines: _DEBUG stays undefined, so the #else branch of the
    // VERSIONINFO FILEFLAGS conditional is taken (matching the golden).
    let unit = rc::compile_file(&rc_path, &HashMap::new())
        .unwrap_or_else(|e| panic!("RAILC.RC failed to compile: {e}"));

    // Increments 2-9: the BC4.5-profile writer reproduces the golden.
    let ours = rc::write_res_bc45(&unit);

    let our_recs = parse_res(&ours);
    let golden_recs = parse_res(&golden);

    // Record-by-record inventory + payload comparison (readable diffs
    // before the blunt full-stream assert).
    let n = our_recs.len().min(golden_recs.len());
    for i in 0..n {
        let (o, g) = (&our_recs[i], &golden_recs[i]);
        assert_eq!(
            (o.rtype.clone(), o.name.clone(), o.lang, o.mem, o.data.len()),
            (g.rtype.clone(), g.name.clone(), g.lang, g.mem, g.data.len()),
            "record [{i}] header mismatch:\n  ours:   {}\n  golden: {}",
            describe(o),
            describe(g),
        );
        if let Some(off) = first_diff(&o.data, &g.data) {
            panic!(
                "record [{i}] ({}) payload differs at byte {off}:\n  ours:   {:02x?}\n  golden: {:02x?}",
                describe(g),
                &o.data[off..(off + 16).min(o.data.len())],
                &g.data[off..(off + 16).min(g.data.len())],
            );
        }
    }
    assert_eq!(
        our_recs.len(),
        golden_recs.len(),
        "record count mismatch: ours has {} records, golden has {} \
         (first unmatched: {})",
        our_recs.len(),
        golden_recs.len(),
        if our_recs.len() > golden_recs.len() {
            describe(&our_recs[n])
        } else {
            describe(&golden_recs[n])
        },
    );

    // The final ratchet: byte-identical stream (framing + padding too).
    assert_eq!(
        ours.len(),
        golden.len(),
        "stream length mismatch despite matching records (padding rules?)"
    );
    if let Some(off) = first_diff(&ours, &golden) {
        panic!(
            "full-stream byte difference at offset {off}:\n  ours:   {:02x?}\n  golden: {:02x?}",
            &ours[off..(off + 16).min(ours.len())],
            &golden[off..(off + 16).min(golden.len())],
        );
    }
}
