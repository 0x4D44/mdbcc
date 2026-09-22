//! G2 — `.res` binary-writer byte-exact differential vs Borland brc32.
//!
//! Each test compares `mdbcc::rc::write_res(&parse(rc_src))` against
//! `brc32 -r -fo out.res in.rc` when the `wrk_tools/BCC55/Bin/brc32.exe`
//! binary is present, falling back to a hand-computed golden when it is
//! not (mirroring the `Option<Bcc>` pattern in `tests/differential.rs`).
//!
//! The hand-goldens encode the exact same byte layout I observed on
//! brc32 5.40 in the sandbox; this guarantees the suite catches any
//! regression even when brc32 is absent in CI.
//!
//! Layout invariants exercised:
//!
//! 1. Every file starts with a 32-byte null-header sentinel.
//! 2. Each resource record has a 32-byte ResHeader (data_size,
//!    header_size, type ordinal, name ordinal, data_version, mem_flags,
//!    language_id, version, characteristics).
//! 3. STRINGTABLE bundle = 16 length-prefixed UTF-16LE strings indexed
//!    by `slot = id & 0xF`; bundle id = `(id >> 4) + 1`.
//! 4. Records are DWORD-padded after their data section.
//! 5. Memory-flags default = 0x1030 (MOVEABLE|PURE|DISCARDABLE).
//! 6. Language-id default (no LANGUAGE statement) = 0x0809.

use std::path::{Path, PathBuf};

use mdbcc::rc::{parse, write_res, write_res_bc45};

// ---------------------------------------------------------------------------
// brc32 oracle
// ---------------------------------------------------------------------------

/// Discovered brc32 binary. `None` when absent — tests gracefully fall
/// back to hand-goldens.
struct Brc {
    exe: PathBuf,
}

impl Brc {
    fn discover() -> Option<Self> {
        let candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("wrk_tools")
            .join("BCC55")
            .join("Bin")
            .join("brc32.exe");
        if candidate.exists() {
            Some(Self { exe: candidate })
        } else {
            None
        }
    }

    /// Compile `rc_bytes` (already-encoded `.rc` source — CP1252 / ASCII
    /// for v1) to a `.res` byte stream using `brc32 -r -fo<out> <in>`.
    /// brc32's `-fo` takes the filename concatenated, no space (verified
    /// against the program's own `-h` output: `-fofilename`).
    ///
    /// The temp directory is owned by an RAII [`TempDir`] guard so a
    /// panic in the asserts below — or a failing read — does not leak the
    /// scratch dir (G-fix MINOR-4 from the Phase G review).
    fn compile(&self, rc_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        let dir = TempDir::new(format!("mdbcc_rc_g2_{}_{}", std::process::id(), rand_tag()))?;
        let rc_path = dir.path().join("in.rc");
        let res_path = dir.path().join("out.res");
        std::fs::write(&rc_path, rc_bytes)?;

        let fo_arg = format!("-fo{}", res_path.display());
        let status = std::process::Command::new(&self.exe)
            .arg("-r")
            .arg(&fo_arg)
            .arg(&rc_path)
            .current_dir(dir.path())
            .status()?;
        assert!(
            status.success(),
            "brc32 -r -fo<out> <in> failed (status {status:?})"
        );

        std::fs::read(&res_path)
    }
}

/// RAII guard that removes its temp directory on drop, regardless of
/// happy-path vs panic. Previously the cleanup at the end of
/// [`Brc::compile`] was bypassed on assertion failure, leaving a
/// growing pile of scratch dirs (G-fix MINOR-4).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: String) -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Cheap unique tag per call so concurrent tests don't collide on the
/// same scratch dir. No external dependency — derived from a fast
/// monotonic clock + a per-call counter.
fn rand_tag() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{now:x}_{c}")
}

/// Drive a single corpus entry: compare `write_res(parse(utf8_src))`
/// against either brc32's output for `oracle_src` (when available) or
/// the supplied hand-golden. `oracle_src` and `utf8_src` are usually
/// the same string; they differ only for the Unicode test, where
/// brc32 wants CP1252 single-byte 0xE9 while our parser wants UTF-8.
fn compare(utf8_src: &str, oracle_src: &[u8], hand_golden: &[u8]) {
    let unit = parse(utf8_src).expect("rc parse ok");
    let ours = write_res(&unit);

    let expected = match Brc::discover() {
        Some(brc) => brc
            .compile(oracle_src)
            .expect("brc32 compile ok (oracle present)"),
        None => hand_golden.to_vec(),
    };

    assert_eq!(
        ours,
        expected,
        "\nmdbcc .res differs from oracle.\n  ours    ({} bytes)\n  expected({} bytes)\n  ours    : {}\n  expected: {}",
        ours.len(),
        expected.len(),
        hex(&ours),
        hex(&expected),
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

// ---------------------------------------------------------------------------
// Hand-golden helpers — keep tests readable.
// ---------------------------------------------------------------------------

const NULL_HEADER: [u8; 32] = [
    0, 0, 0, 0, // data_size
    32, 0, 0, 0, // header_size
    0xFF, 0xFF, 0, 0, // type ordinal (null)
    0xFF, 0xFF, 0, 0, // name ordinal (null)
    0, 0, 0, 0, // data_version
    0, 0, // memory_flags
    0, 0, // language_id
    0, 0, 0, 0, // version
    0, 0, 0, 0, // characteristics
];

/// Build a ResHeader for an RT_STRING record with the given bundle id,
/// data_size, memory_flags, and language_id.
fn res_hdr(data_size: u32, bundle_id: u16, mem_flags: u16, lang: u16) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(&data_size.to_le_bytes());
    h[4..8].copy_from_slice(&32u32.to_le_bytes()); // header_size
    h[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
    h[10..12].copy_from_slice(&6u16.to_le_bytes()); // RT_STRING
    h[12..14].copy_from_slice(&0xFFFFu16.to_le_bytes());
    h[14..16].copy_from_slice(&bundle_id.to_le_bytes());
    h[16..20].copy_from_slice(&0u32.to_le_bytes()); // data_version
    h[20..22].copy_from_slice(&mem_flags.to_le_bytes());
    h[22..24].copy_from_slice(&lang.to_le_bytes());
    h[24..28].copy_from_slice(&0u32.to_le_bytes()); // version
    h[28..32].copy_from_slice(&0u32.to_le_bytes()); // characteristics
    h
}

/// Build a 16-slot bundle payload from a sparse `[(slot, &str); N]`
/// list, where unlisted slots become empty (u16 0). Mirrors the writer
/// faithfully so the hand-goldens are easy to derive.
fn bundle_data(slots: &[(usize, &str)]) -> Vec<u8> {
    let mut filled: [Option<&str>; 16] = Default::default();
    for &(i, s) in slots {
        filled[i] = Some(s);
    }
    let mut out = Vec::new();
    for slot in filled {
        match slot {
            None => out.extend_from_slice(&0u16.to_le_bytes()),
            Some(s) => {
                let utf16: Vec<u16> = s.encode_utf16().collect();
                out.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
                for u in utf16 {
                    out.extend_from_slice(&u.to_le_bytes());
                }
            }
        }
    }
    out
}

fn pad_to_dword(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Build a complete hand-golden `.res` byte stream: null header
/// followed by one record per `(bundle_id, data_size, flags, lang, data)`
/// quadruple. Pads each record to DWORD.
fn build_golden(records: &[(u16, u16, u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&NULL_HEADER);
    for (bundle_id, mem_flags, lang, data) in records {
        let hdr = res_hdr(data.len() as u32, *bundle_id, *mem_flags, *lang);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
        pad_to_dword(&mut out);
    }
    out
}

// Memory/language constants — duplicated from src/rc/res.rs so the
// goldens read independently of the writer's internal constants.
const FLAGS_DEFAULT: u16 = 0x1030; // MOVEABLE | PURE | DISCARDABLE
const FLAGS_PRELOAD: u16 = 0x1070; // + PRELOAD
const FLAGS_FIXED: u16 = 0x1020; // base &~ MOVEABLE
const LANG_DEFAULT: u16 = 0x0809; // brc32 compiled-in default (en-GB)
const LANG_EN_US: u16 = 0x0409;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. An empty unit (no resources) ⇒ exactly the 32-byte null header.
#[test]
fn empty_unit_emits_just_null_header() {
    let unit = mdbcc::rc::RcUnit::default();
    let bytes = write_res(&unit);
    assert_eq!(bytes, NULL_HEADER.to_vec());
    assert_eq!(bytes.len(), 32);
}

/// 2. Single string id=1 ⇒ one RT_STRING record at bundle 1.
#[test]
fn single_string_id_1() {
    let src = include_str!("corpus/rc/stringtable_simple.rc");
    let data = bundle_data(&[(1, "hello")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// 3. Three ids all in bundle 1 (1, 5, 7) ⇒ a single record.
#[test]
fn multiple_ids_same_bundle() {
    let src = "STRINGTABLE\nBEGIN\n  1 \"one\"\n  5 \"five\"\n  7 \"seven\"\nEND\n";
    let data = bundle_data(&[(1, "one"), (5, "five"), (7, "seven")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// 4. ids 1 and 17 ⇒ two records (bundles 1 and 2).
#[test]
fn multiple_ids_different_bundles() {
    let src = include_str!("corpus/rc/stringtable_multibundle.rc");
    let data1 = bundle_data(&[(1, "one")]);
    let data2 = bundle_data(&[(1, "seventeen")]); // 17 & 0xF = 1
    let golden = build_golden(&[
        (1, FLAGS_DEFAULT, LANG_DEFAULT, data1),
        (2, FLAGS_DEFAULT, LANG_DEFAULT, data2),
    ]);
    compare(src, src.as_bytes(), &golden);
}

/// Test 5: `STRINGTABLE DISCARDABLE` — the DISCARDABLE bit is already
/// set in the default, so the emitted mem_flags is unchanged (0x1030).
/// brc32-observed.
#[test]
fn discardable_flag_is_noop_with_default_already_discardable() {
    let src = "STRINGTABLE DISCARDABLE\nBEGIN\n  1 \"x\"\nEND\n";
    let data = bundle_data(&[(1, "x")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// 5b. `STRINGTABLE PRELOAD` — sets bit 0x40 atop the default ⇒ 0x1070.
#[test]
fn preload_flag_sets_bit() {
    let src = "STRINGTABLE PRELOAD\nBEGIN\n  1 \"x\"\nEND\n";
    let data = bundle_data(&[(1, "x")]);
    let golden = build_golden(&[(1, FLAGS_PRELOAD, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// 5c. `STRINGTABLE FIXED` — clears the MOVEABLE bit ⇒ 0x1020.
#[test]
fn fixed_flag_clears_moveable() {
    let src = "STRINGTABLE FIXED\nBEGIN\n  1 \"x\"\nEND\n";
    let data = bundle_data(&[(1, "x")]);
    let golden = build_golden(&[(1, FLAGS_FIXED, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// 6. `LANGUAGE 0x09, 0x01` (file-level) ⇒ language_id = 0x0409 (en-US).
#[test]
fn language_en_us() {
    let src = include_str!("corpus/rc/stringtable_lang.rc");
    let data = bundle_data(&[(1, "hi")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_EN_US, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// Test 7: no LANGUAGE statement ⇒ brc32's compiled-in default
/// language_id (0x0809). Pins down "the language brc32 chooses when
/// not told".
#[test]
fn language_default_when_unspecified() {
    let src = "STRINGTABLE\nBEGIN\n  1 \"x\"\nEND\n";
    let data = bundle_data(&[(1, "x")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// Test 8: non-ASCII string `"café"` (é = U+00E9). The writer encodes
/// via `encode_utf16` ⇒ four code units 0x63 0x61 0x66 0x00E9.
///
/// brc32 reads CP1252 source — the on-disk fixture stores é as the
/// single byte 0xE9. Our parser reads UTF-8, so the strings differ on
/// disk but encode identically to UTF-16LE.
#[test]
fn utf16_string_encoding_of_latin1() {
    // brc32 input: CP1252 (é = 0xE9 single byte)
    let oracle = b"STRINGTABLE\r\nBEGIN\r\n    1 \"caf\xe9\"\r\nEND\r\n";
    // mdbcc parser input: UTF-8 (é = 0xC3 0xA9)
    let utf8_src = "STRINGTABLE\nBEGIN\n  1 \"café\"\nEND\n";

    // Hand-golden: length 4, then 0x63 0x00 0x61 0x00 0x66 0x00 0xE9 0x00.
    let data = bundle_data(&[(1, "café")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    compare(utf8_src, oracle, &golden);
}

/// Test 9: DWORD alignment — a 3-char value gives data_size = 0x26
/// (not DWORD-aligned). The writer must pad the record's tail to the
/// next DWORD with zero bytes. Total file size = 32 + 32 + 38 + 2 = 104.
#[test]
fn dword_alignment_padding_after_record() {
    let src = include_str!("corpus/rc/stringtable_align.rc");
    let data = bundle_data(&[(1, "abc")]);
    assert_eq!(data.len(), 38, "bundle data should be 38 bytes for 'abc'");
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    assert_eq!(golden.len(), 104, "padded total should be 104 bytes");
    compare(src, src.as_bytes(), &golden);
}

/// Test 10: two STRINGTABLE blocks parsed independently must produce
/// the same .res as a single merged block. Verified against brc32: the
/// resource compiler bundles across blocks by `(id >> 4) + 1`.
#[test]
fn multiple_stringtable_blocks_merge_into_one_bundle() {
    let src = "STRINGTABLE\nBEGIN\n  1 \"first\"\nEND\n\nSTRINGTABLE\nBEGIN\n  5 \"second\"\nEND\n";
    let data = bundle_data(&[(1, "first"), (5, "second")]);
    let golden = build_golden(&[(1, FLAGS_DEFAULT, LANG_DEFAULT, data)]);
    compare(src, src.as_bytes(), &golden);
}

/// 11 (extra). Two blocks contributing to *different* bundles → two
/// records, in ascending bundle-id order. Just confirms cross-block
/// bundle-id grouping doesn't merge unrelated bundles.
#[test]
fn two_blocks_separate_bundles_yields_two_records() {
    let src =
        "STRINGTABLE\nBEGIN\n  1 \"first\"\nEND\n\nSTRINGTABLE\nBEGIN\n  17 \"second\"\nEND\n";
    let data1 = bundle_data(&[(1, "first")]);
    let data2 = bundle_data(&[(1, "second")]); // 17 & 0xF = 1
    let golden = build_golden(&[
        (1, FLAGS_DEFAULT, LANG_DEFAULT, data1),
        (2, FLAGS_DEFAULT, LANG_DEFAULT, data2),
    ]);
    compare(src, src.as_bytes(), &golden);
}

/// G-fix MINOR-7: bundle-id boundary math at id=0, id=15, and id=65535
/// (the three extremes the existing fixtures don't exercise). brc32 5.40
/// verified empirically:
///   id=0     ⇒ bundle 1, slot 0
///   id=15    ⇒ bundle 1, slot 15
///   id=65535 ⇒ bundle 4096, slot 15  (max u16 bundle id)
/// A future off-by-one in `(id >> 4) + 1` or `id & 0xF` would be caught
/// at all three edges.
#[test]
fn g_fix_minor_7_stringtable_id_boundaries() {
    let src = "STRINGTABLE\nBEGIN\n  0 \"zero\"\n  15 \"fifteen\"\n  65535 \"max\"\nEND\n";
    // ids 0 and 15 share bundle 1 (slots 0 and 15).
    let bundle_1_data = bundle_data(&[(0, "zero"), (15, "fifteen")]);
    // id 65535 lives alone in bundle 4096 at slot 15.
    let bundle_4096_data = bundle_data(&[(15, "max")]);
    let golden = build_golden(&[
        (1, FLAGS_DEFAULT, LANG_DEFAULT, bundle_1_data),
        (4096, FLAGS_DEFAULT, LANG_DEFAULT, bundle_4096_data),
    ]);
    compare(src, src.as_bytes(), &golden);
}

/// 12 (extra). Block-level LANGUAGE overrides file-level LANGUAGE for
/// that block's bundles. Pins down precedence rules so a future
/// refactor can't silently invert them.
#[test]
fn block_language_overrides_file_language() {
    let src = "LANGUAGE 0x07, 0x01\nSTRINGTABLE\nLANGUAGE 0x10, 0x01\nBEGIN\n  1 \"hi\"\nEND\n";
    let data = bundle_data(&[(1, "hi")]);
    let block_lang = 0x10u16 | (0x01u16 << 10); // 0x0410
    let golden = build_golden(&[(1, FLAGS_DEFAULT, block_lang, data)]);
    compare(src, src.as_bytes(), &golden);
}

// ---------------------------------------------------------------------------
// G4 — MENU + ACCELERATORS .res differential vs brc32
// ---------------------------------------------------------------------------
//
// brc32 5.40's observed type-ordinals + mem_flags for G4 resources:
//   - RT_MENU       (4)  default mem_flags = 0x1030 (MOVEABLE|PURE|DISCARDABLE)
//   - RT_ACCELERATOR(9)  default mem_flags = 0x0030 (MOVEABLE|PURE)
//                        - folklore-busting: no DISCARDABLE bit, unlike MENU
// The default language is the same 0x0809 (en-GB) the STRINGTABLE tests use.

const FLAGS_MENU_DEFAULT: u16 = 0x1030;
const FLAGS_ACCEL_DEFAULT: u16 = 0x0030;
const FLAGS_VERSION_DEFAULT: u16 = 0x0030;
const RT_MENU_ORD: u16 = 4;
const RT_ACCEL_ORD: u16 = 9;
const RT_VERSION_ORD: u16 = 16;

/// Build a ResHeader for any resource type ordinal (parameterised so the
/// G4 tests can use the same helper for RT_MENU/RT_ACCELERATOR as the G2
/// helper did for RT_STRING).
fn res_hdr_typed(
    data_size: u32,
    type_ord: u16,
    name_ord: u16,
    mem_flags: u16,
    lang: u16,
) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(&data_size.to_le_bytes());
    h[4..8].copy_from_slice(&32u32.to_le_bytes());
    h[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
    h[10..12].copy_from_slice(&type_ord.to_le_bytes());
    h[12..14].copy_from_slice(&0xFFFFu16.to_le_bytes());
    h[14..16].copy_from_slice(&name_ord.to_le_bytes());
    h[16..20].copy_from_slice(&0u32.to_le_bytes());
    h[20..22].copy_from_slice(&mem_flags.to_le_bytes());
    h[22..24].copy_from_slice(&lang.to_le_bytes());
    h[24..28].copy_from_slice(&0u32.to_le_bytes());
    h[28..32].copy_from_slice(&0u32.to_le_bytes());
    h
}

/// Build a ResHeader for a named resource. Type stays an ordinal; name is a
/// UTF-16LE NUL string followed by DWORD padding before the fixed tail.
fn res_hdr_typed_named(
    data_size: u32,
    type_ord: u16,
    name: &str,
    mem_flags: u16,
    lang: u16,
) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&data_size.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&0xFFFFu16.to_le_bytes());
    h.extend_from_slice(&type_ord.to_le_bytes());
    h.extend_from_slice(&utf16le_nul(name));
    pad_to_dword(&mut h);
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&mem_flags.to_le_bytes());
    h.extend_from_slice(&lang.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    let header_size = h.len() as u32;
    h[4..8].copy_from_slice(&header_size.to_le_bytes());
    h
}

fn version_payload_golden() -> Vec<u8> {
    let string_table = version_block_bytes(
        "040904E4",
        vec![
            version_value_bytes("CompanyName", "MD Soft\0\0"),
            version_value_bytes("FileVersion", "2.3\0"),
        ],
    );
    let string_file_info = version_block_bytes("StringFileInfo", vec![string_table]);

    let mut out = version_node_prefix(52, 0, "VS_VERSION_INFO");
    push_version_fixed(
        &mut out,
        VersionFixed {
            file_version: [2, 3, 0, 0],
            product_version: [2, 3, 0, 0],
            flags_mask: 0x20,
            flags: 0,
            os: 1,
            file_type: 1,
            subtype: 0,
        },
    );
    pad_to_dword(&mut out);
    out.extend_from_slice(&string_file_info);
    finish_version_node(&mut out);
    out
}

fn version_block_bytes(key: &str, children: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = version_node_prefix(0, 0, key);
    for child in children {
        pad_to_dword(&mut out);
        out.extend_from_slice(&child);
    }
    finish_version_node(&mut out);
    out
}

fn version_value_bytes(key: &str, value: &str) -> Vec<u8> {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let mut out = version_node_prefix(utf16.len() as u16, 1, key);
    for unit in utf16 {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    finish_version_node(&mut out);
    out
}

fn version_node_prefix(value_len: u16, value_type: u16, key: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&value_len.to_le_bytes());
    out.extend_from_slice(&value_type.to_le_bytes());
    out.extend_from_slice(&utf16le_nul(key));
    pad_to_dword(&mut out);
    out
}

fn finish_version_node(out: &mut [u8]) {
    let len = out.len() as u16;
    out[0..2].copy_from_slice(&len.to_le_bytes());
}

struct VersionFixed {
    file_version: [u16; 4],
    product_version: [u16; 4],
    flags_mask: u32,
    flags: u32,
    os: u32,
    file_type: u32,
    subtype: u32,
}

fn push_version_fixed(out: &mut Vec<u8>, fixed: VersionFixed) {
    out.extend_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    out.extend_from_slice(&0x0001_0000u32.to_le_bytes());
    push_version_quad(out, fixed.file_version);
    push_version_quad(out, fixed.product_version);
    out.extend_from_slice(&fixed.flags_mask.to_le_bytes());
    out.extend_from_slice(&fixed.flags.to_le_bytes());
    out.extend_from_slice(&fixed.os.to_le_bytes());
    out.extend_from_slice(&fixed.file_type.to_le_bytes());
    out.extend_from_slice(&fixed.subtype.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
}

fn push_version_quad(out: &mut Vec<u8>, quad: [u16; 4]) {
    let ms = ((quad[0] as u32) << 16) | quad[1] as u32;
    let ls = ((quad[2] as u32) << 16) | quad[3] as u32;
    out.extend_from_slice(&ms.to_le_bytes());
    out.extend_from_slice(&ls.to_le_bytes());
}

/// Encode a UTF-8 string as UTF-16LE plus a u16 NUL terminator. Used by
/// the MENU hand-goldens (item text is null-terminated, not length-
/// prefixed, unlike STRINGTABLE).
fn utf16le_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Append a MENUITEM leaf (flags, id, text\0) to `out`.
fn push_item(out: &mut Vec<u8>, flags: u16, id: u16, text: &str) {
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&utf16le_nul(text));
}

/// Append a POPUP header (flags|MF_POPUP, text\0). Nested items follow
/// directly. The caller is responsible for writing the inner items.
fn push_popup(out: &mut Vec<u8>, flags: u16, text: &str) {
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&utf16le_nul(text));
}

/// Wrap one MENU resource record around its `data` payload and append it
/// to `out`, including the DWORD trailing pad.
fn push_menu_record(out: &mut Vec<u8>, id: u16, data: Vec<u8>) {
    let hdr = res_hdr_typed(
        data.len() as u32,
        RT_MENU_ORD,
        id,
        FLAGS_MENU_DEFAULT,
        LANG_DEFAULT,
    );
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&data);
    pad_to_dword(out);
}

/// Wrap one ACCELERATORS resource record around its `data` payload.
fn push_accel_record(out: &mut Vec<u8>, id: u16, data: Vec<u8>) {
    let hdr = res_hdr_typed(
        data.len() as u32,
        RT_ACCEL_ORD,
        id,
        FLAGS_ACCEL_DEFAULT,
        LANG_DEFAULT,
    );
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&data);
    pad_to_dword(out);
}

/// G4-1: simplest MENU — one POPUP ("File") containing one MENUITEM
/// ("Exit", 200). Verifies the MenuHeader + nested POPUP/MENUITEM
/// emission with MF_END set on the last sibling at each level.
#[test]
fn g4_menu_one_popup_one_item() {
    let src = include_str!("corpus/rc/menu_simple.rc");
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]); // MenuHeader: wVersion=0, wOffset=0
    push_popup(&mut data, 0x0090, "File"); // MF_POPUP|MF_END (last & only)
    push_item(&mut data, 0x0080, 200, "Exit"); // MF_END inside popup
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_menu_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G4-2: MENU with a SEPARATOR — a MENUITEM with empty text and id 0.
/// Folklore-busting: brc32 does NOT set MF_SEPARATOR=0x0800; the encoded
/// flags are just MF_END (when last) or 0.
#[test]
fn g4_menu_with_separator() {
    let src = include_str!("corpus/rc/menu_separator.rc");
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]); // MenuHeader
    push_popup(&mut data, 0x0090, "File"); // MF_POPUP|MF_END
    push_item(&mut data, 0x0000, 200, "Open"); // first item: no flags
    // Separator: flags=0 (not last inside popup), id=0, empty text \0
    data.extend_from_slice(&[0, 0]); // flags=0
    data.extend_from_slice(&[0, 0]); // id=0
    data.extend_from_slice(&[0, 0]); // empty UTF-16LE string = just NUL
    push_item(&mut data, 0x0080, 201, "Exit"); // MF_END (last in popup)
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_menu_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G4-3: MENU with two POPUPs ("File" + "Help"), each with one MENUITEM.
/// Verifies that only the LAST top-level item gets MF_END, and the
/// MF_END/MF_POPUP combination on the final popup is 0x0090.
#[test]
fn g4_menu_two_popups() {
    let src = include_str!("corpus/rc/menu_twopopup.rc");
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]); // MenuHeader
    push_popup(&mut data, 0x0010, "File"); // MF_POPUP only (not last)
    push_item(&mut data, 0x0000, 200, "Open");
    push_item(&mut data, 0x0080, 201, "Exit"); // MF_END (last in popup)
    push_popup(&mut data, 0x0090, "Help"); // MF_POPUP|MF_END (last popup)
    push_item(&mut data, 0x0080, 300, "About"); // MF_END
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_menu_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// W5 rc gap 5: a named top-level MENU emits a string-form ResHeader name.
/// Full railc source-order/default-language profiling stays gap 6; this pins
/// only the new ResId::Name path without disturbing ordinal resources.
#[test]
fn g5_named_menu_res_header_uses_string_name() {
    let src = "\
MAIN_MENU MENU
BEGIN
  POPUP \"File\"
  BEGIN
    MENUITEM \"Exit\", 200
  END
END
";
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]); // MenuHeader
    push_popup(&mut data, 0x0090, "File");
    push_item(&mut data, 0x0080, 200, "Exit");

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    golden.extend_from_slice(&res_hdr_typed_named(
        data.len() as u32,
        RT_MENU_ORD,
        "MAIN_MENU",
        FLAGS_MENU_DEFAULT,
        LANG_DEFAULT,
    ));
    golden.extend_from_slice(&data);
    pad_to_dword(&mut golden);

    compare(src, src.as_bytes(), &golden);
}

/// W5 rc gap 7: inline ICON/BITMAP/RCDATA payloads are cooked into Win32
/// .res records. ICON splits into RT_ICON (#3, ordinal name) followed by
/// RT_GROUP_ICON (#14, source name); BITMAP strips the BITMAPFILEHEADER;
/// RCDATA stays opaque.
#[test]
fn g7_binary_resources_emit_res_records() {
    let src = "\
APPICON ICON
BEGIN
  '00 00 01 00 01 00 20 20 10 00 00 00 00 00 10 00 00 00 16 00 00 00'
  '28 00 00 00 00 00 00 00 00 00 00 00 01 00 04 00'
END
SPLASH BITMAP
BEGIN
  '42 4D 3A 00 00 00 00 00 00 00 36 00 00 00'
  '28 00 00 00 01 00 00 00 01 00 00 00 01 00 20 00 00 00 00 00 00 00 00 00'
  '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF 00 00 00'
END
BEEP RCDATA
BEGIN
  '52 49 46 46'
END
";
    let unit = parse(src).expect("parse ok");
    let ours = write_res(&unit);

    let image = vec![0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4, 0];
    let group = vec![
        0, 0, 1, 0, 1, 0, 0x20, 0x20, 0x10, 0, 1, 0, 4, 0, 0x10, 0, 0, 0, 1, 0,
    ];
    let bitmap = vec![
        0x28, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0x20, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0,
    ];

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    golden.extend_from_slice(&res_hdr_typed(
        image.len() as u32,
        3,
        1,
        0x1010,
        LANG_DEFAULT,
    ));
    golden.extend_from_slice(&image);
    pad_to_dword(&mut golden);
    golden.extend_from_slice(&res_hdr_typed_named(
        group.len() as u32,
        14,
        "APPICON",
        0x1030,
        LANG_DEFAULT,
    ));
    golden.extend_from_slice(&group);
    pad_to_dword(&mut golden);
    golden.extend_from_slice(&res_hdr_typed_named(
        bitmap.len() as u32,
        2,
        "SPLASH",
        0x0030,
        LANG_DEFAULT,
    ));
    golden.extend_from_slice(&bitmap);
    pad_to_dword(&mut golden);
    golden.extend_from_slice(&res_hdr_typed_named(4, 10, "BEEP", 0x0030, LANG_DEFAULT));
    golden.extend_from_slice(b"RIFF");
    pad_to_dword(&mut golden);

    assert_eq!(ours, golden);
}

/// W5 rc gap 8: VERSIONINFO emits a standard RT_VERSION (#16)
/// VS_VERSION_INFO tree. Borland's VALUE `wValueLength` is the exact
/// number of UTF-16 code units in the source strings; it does not append
/// an implicit NUL, so explicit `\0` padding is preserved here.
#[test]
fn g8_versioninfo_emits_res_record() {
    let src = r#"
1 VERSIONINFO
 FILEVERSION 2,3,0,0
 PRODUCTVERSION 2,3,0,0
 FILEFLAGSMASK 0x20L
 FILEFLAGS 0x0L
 FILEOS 0x1L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904E4"
    BEGIN
      VALUE "CompanyName", "MD Soft\0", "\0"
      VALUE "FileVersion", "2.3\0"
    END
  END
END
"#;
    let data = version_payload_golden();
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    golden.extend_from_slice(&res_hdr_typed(
        data.len() as u32,
        RT_VERSION_ORD,
        1,
        FLAGS_VERSION_DEFAULT,
        LANG_DEFAULT,
    ));
    golden.extend_from_slice(&data);
    pad_to_dword(&mut golden);

    compare(src, src.as_bytes(), &golden);
}

/// W5 rc gap 6: RailC's BC4.5-era `.res` profile differs from the brc32
/// 5.40 profile pinned by `write_res`: non-string resources are emitted in
/// source order, string bundles are emitted last, and the implicit language
/// id is 0.
#[test]
fn g6_bc45_profile_uses_source_order_strings_last_and_lang_zero() {
    let src = r#"
1 VERSIONINFO
 FILEVERSION 2,3,0,0
 PRODUCTVERSION 2,3,0,0
 FILEFLAGSMASK 0x20L
 FILEFLAGS 0x0L
 FILEOS 0x1L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904E4"
    BEGIN
      VALUE "CompanyName", "MD Soft\0", "\0"
      VALUE "FileVersion", "2.3\0"
    END
  END
END

2 MENU
BEGIN
END

STRINGTABLE
BEGIN
  1 "hello"
END
"#;
    let unit = parse(src).expect("parse ok");
    let ours = write_res_bc45(&unit);

    let version = version_payload_golden();
    let menu = vec![0, 0, 0, 0];
    let strings = bundle_data(&[(1, "hello")]);

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    golden.extend_from_slice(&res_hdr_typed(
        version.len() as u32,
        RT_VERSION_ORD,
        1,
        FLAGS_VERSION_DEFAULT,
        0,
    ));
    golden.extend_from_slice(&version);
    pad_to_dword(&mut golden);
    golden.extend_from_slice(&res_hdr_typed(
        menu.len() as u32,
        RT_MENU_ORD,
        2,
        FLAGS_MENU_DEFAULT,
        0,
    ));
    golden.extend_from_slice(&menu);
    pad_to_dword(&mut golden);
    golden.extend_from_slice(&res_hdr_typed(strings.len() as u32, 6, 1, FLAGS_DEFAULT, 0));
    golden.extend_from_slice(&strings);
    pad_to_dword(&mut golden);

    assert_eq!(ours, golden);
}

/// G4-4: ACCELERATORS with one ASCII (`^O`) entry. brc32-observed:
/// `^O` is cooked to 0x0F at parse time; the FACCEL_CONTROL bit is NOT
/// set (folklore-busting — most descriptions of the format say `^X`
/// should leave the original char + CONTROL flag, but brc32 5.40
/// emits the post-Ctrl byte and a clear flag word). The only fFlags bit
/// set on the lone entry is FACCEL_LAST=0x80.
#[test]
fn g4_accel_ascii_ctrl() {
    let src = include_str!("corpus/rc/accel_ascii.rc");
    let mut data = Vec::new();
    // entry: fFlags=0x80 (LAST only), pad=0, key=0x0F (Ctrl-O), cmd=200, pad=0
    data.extend_from_slice(&[0x80, 0x00]);
    data.extend_from_slice(&0x000Fu16.to_le_bytes());
    data.extend_from_slice(&200u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_accel_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G4-5: ACCELERATORS with one VIRTKEY entry (numeric VK code).
/// fFlags = FACCEL_VIRTKEY | FACCEL_LAST = 0x81.
#[test]
fn g4_accel_virtkey() {
    let src = include_str!("corpus/rc/accel_virtkey.rc");
    let mut data = Vec::new();
    data.extend_from_slice(&[0x81, 0x00]); // VIRTKEY|LAST
    data.extend_from_slice(&0x0070u16.to_le_bytes()); // VK_F1
    data.extend_from_slice(&300u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_accel_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G4-6: ACCELERATORS with multi-flag entries — VIRTKEY|CONTROL,
/// VIRTKEY|CONTROL|SHIFT, VIRTKEY|NOINVERT|LAST. Verifies all the
/// FACCEL_* bits combine correctly.
#[test]
fn g4_accel_multiple_flags() {
    let src = include_str!("corpus/rc/accel_multi.rc");
    let mut data = Vec::new();
    // 1: VIRTKEY|CONTROL = 0x09, key='S'=0x53, cmd=200
    data.extend_from_slice(&[0x09, 0x00]);
    data.extend_from_slice(&0x0053u16.to_le_bytes());
    data.extend_from_slice(&200u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    // 2: VIRTKEY|CONTROL|SHIFT = 0x0D, key='Z'=0x5A, cmd=201
    data.extend_from_slice(&[0x0D, 0x00]);
    data.extend_from_slice(&0x005Au16.to_le_bytes());
    data.extend_from_slice(&201u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    // 3: VIRTKEY|NOINVERT|LAST = 0x83, key=0x1B (VK_ESCAPE), cmd=202
    data.extend_from_slice(&[0x83, 0x00]);
    data.extend_from_slice(&0x001Bu16.to_le_bytes());
    data.extend_from_slice(&202u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_accel_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

// ---------------------------------------------------------------------------
// G5a — DIALOG .res differential vs brc32
// ---------------------------------------------------------------------------
//
// brc32 5.40 type-internal emission order with DIALOG present:
//   MENU (4) → DIALOG (5) → ACCELERATORS (9) → STRINGTABLE (6).
//   Verified empirically — folklore-busting, since the order is NOT
//   ascending type-ordinal (ACCEL=9 comes before STRINGTABLE=6).
//
// DIALOG payload defaults observed against brc32 5.40:
//   - mem_flags = 0x1030 (MOVEABLE|PURE|DISCARDABLE) — same as MENU.
//   - language = 0x0809 (en-GB) when no LANGUAGE statement.
//   - default style when STYLE statement absent = 0x80880000 (= WS_POPUP|
//     WS_BORDER|WS_SYSMENU). NOT WS_POPUP|WS_CAPTION|WS_SYSMENU as some
//     references claim.
//   - CAPTION presence OR's in WS_CAPTION (0x00C00000).
//   - FONT presence OR's in DS_SETFONT (0x00000040).
//   - Shorthand control defaults (PUSHBUTTON, LTEXT, …) per HLD §G5.
//   - Predefined class strings ("BUTTON"/"EDIT"/"STATIC"/…) in generic
//     CONTROL form are normalised to the {0xFFFF, ord} ordinal form.

const FLAGS_DIALOG_DEFAULT: u16 = 0x1030;
const RT_DIALOG_ORD: u16 = 5;

/// Encode a UTF-8 string as UTF-16LE with no trailing NUL. Used for
/// hand-golden assembly where the caller wants to control the
/// terminator placement.
fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Pad `buf` with zero bytes until DWORD-aligned.
fn align_dword(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Wrap one DIALOG resource record around its `data` payload.
fn push_dialog_record(out: &mut Vec<u8>, id: u16, data: Vec<u8>) {
    let hdr = res_hdr_typed(
        data.len() as u32,
        RT_DIALOG_ORD,
        id,
        FLAGS_DIALOG_DEFAULT,
        LANG_DEFAULT,
    );
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&data);
    pad_to_dword(out);
}

/// G5a-1: Empty DIALOG — no controls, no statements. Verifies the
/// minimal DLGTEMPLATE header bytes (18 fixed + 6 zero sz_or_ords = 24).
/// brc32-default style 0x80880000.
#[test]
fn g5a_dialog_empty() {
    let src = include_str!("corpus/rc/dialog_empty.rc");
    let mut data = Vec::new();
    // DLGTEMPLATE header
    data.extend_from_slice(&0x8088_0000u32.to_le_bytes()); // style
    data.extend_from_slice(&0u32.to_le_bytes()); // ex_style
    data.extend_from_slice(&0u16.to_le_bytes()); // cdit
    data.extend_from_slice(&0i16.to_le_bytes()); // x
    data.extend_from_slice(&0i16.to_le_bytes()); // y
    data.extend_from_slice(&100i16.to_le_bytes()); // cx
    data.extend_from_slice(&50i16.to_le_bytes()); // cy
    data.extend_from_slice(&0u16.to_le_bytes()); // menu (none)
    data.extend_from_slice(&0u16.to_le_bytes()); // windowClass (none)
    data.extend_from_slice(&0u16.to_le_bytes()); // title (empty)
    align_dword(&mut data);

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_dialog_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G5a-2: DIALOG with CAPTION + FONT. Verifies that CAPTION sets
/// WS_CAPTION (0x00C00000) and FONT sets DS_SETFONT (0x40) in the
/// resolved dialog style, then appends pointSize + typeface after the
/// title.
#[test]
fn g5a_dialog_caption_font() {
    let src = include_str!("corpus/rc/dialog_caption_font.rc");
    let mut data = Vec::new();
    // style = default 0x80880000 | WS_CAPTION 0x00C00000 | DS_SETFONT 0x40
    let style = 0x8088_0000u32 | 0x00C0_0000 | 0x40;
    data.extend_from_slice(&style.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // ex_style
    data.extend_from_slice(&0u16.to_le_bytes()); // cdit
    data.extend_from_slice(&10i16.to_le_bytes()); // x
    data.extend_from_slice(&20i16.to_le_bytes()); // y
    data.extend_from_slice(&200i16.to_le_bytes()); // cx
    data.extend_from_slice(&100i16.to_le_bytes()); // cy
    data.extend_from_slice(&0u16.to_le_bytes()); // menu
    data.extend_from_slice(&0u16.to_le_bytes()); // class
    // title = "Hello\0"
    data.extend_from_slice(&utf16le("Hello"));
    data.extend_from_slice(&0u16.to_le_bytes());
    // FONT trailer: u16 pt + UTF-16LE typeface + u16 NUL.
    data.extend_from_slice(&8u16.to_le_bytes());
    data.extend_from_slice(&utf16le("MS Sans Serif"));
    data.extend_from_slice(&0u16.to_le_bytes());
    align_dword(&mut data);

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_dialog_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G5a-3: DIALOG with one PUSHBUTTON control. Verifies the shorthand
/// expansion: class = predefined BUTTON (0x0080), style = 0x50010000.
/// Also pins the DWORD-alignment between header and DLGITEMTEMPLATE.
#[test]
fn g5a_dialog_one_pushbutton() {
    let src = include_str!("corpus/rc/dialog_pushbutton.rc");
    let mut data = Vec::new();
    // header — CAPTION "Test", default style + WS_CAPTION (no FONT)
    let style = 0x8088_0000u32 | 0x00C0_0000;
    data.extend_from_slice(&style.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // ex_style
    data.extend_from_slice(&1u16.to_le_bytes()); // cdit = 1
    data.extend_from_slice(&0i16.to_le_bytes()); // x
    data.extend_from_slice(&0i16.to_le_bytes()); // y
    data.extend_from_slice(&100i16.to_le_bytes()); // cx
    data.extend_from_slice(&50i16.to_le_bytes()); // cy
    data.extend_from_slice(&0u16.to_le_bytes()); // menu
    data.extend_from_slice(&0u16.to_le_bytes()); // class
    data.extend_from_slice(&utf16le("Test"));
    data.extend_from_slice(&0u16.to_le_bytes()); // title NUL
    align_dword(&mut data);

    // DLGITEMTEMPLATE: PUSHBUTTON "OK", 1, 10, 20, 30, 14. brc32 does NOT
    // append DWORD pad after the last (and only) DLGITEMTEMPLATE — the
    // .res record-level pad covers that; including it here would
    // over-report data_size by 2 bytes.
    data.extend_from_slice(&0x5001_0000u32.to_le_bytes()); // style
    data.extend_from_slice(&0u32.to_le_bytes()); // ex_style
    data.extend_from_slice(&10i16.to_le_bytes()); // x
    data.extend_from_slice(&20i16.to_le_bytes()); // y
    data.extend_from_slice(&30i16.to_le_bytes()); // cx
    data.extend_from_slice(&14i16.to_le_bytes()); // cy
    data.extend_from_slice(&1u16.to_le_bytes()); // id
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // class marker
    data.extend_from_slice(&0x0080u16.to_le_bytes()); // BUTTON
    data.extend_from_slice(&utf16le("OK"));
    data.extend_from_slice(&0u16.to_le_bytes()); // title NUL
    data.extend_from_slice(&0u16.to_le_bytes()); // creationDataLen

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_dialog_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G5a-4: DIALOG with mixed controls — PUSHBUTTON + LTEXT + EDITTEXT.
/// Verifies per-control DWORD alignment between DLGITEMTEMPLATEs, and
/// the EDITTEXT shorthand (no title text; class = EDIT 0x0081; style =
/// 0x50810000).
#[test]
fn g5a_dialog_mixed_controls() {
    let src = include_str!("corpus/rc/dialog_mixed_controls.rc");
    let mut data = Vec::new();
    // header — CAPTION "X"
    let style = 0x8088_0000u32 | 0x00C0_0000;
    data.extend_from_slice(&style.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // ex_style
    data.extend_from_slice(&3u16.to_le_bytes()); // cdit = 3
    data.extend_from_slice(&0i16.to_le_bytes()); // x
    data.extend_from_slice(&0i16.to_le_bytes()); // y
    data.extend_from_slice(&100i16.to_le_bytes()); // cx
    data.extend_from_slice(&50i16.to_le_bytes()); // cy
    data.extend_from_slice(&0u16.to_le_bytes()); // menu
    data.extend_from_slice(&0u16.to_le_bytes()); // class
    data.extend_from_slice(&utf16le("X"));
    data.extend_from_slice(&0u16.to_le_bytes()); // title NUL
    align_dword(&mut data);

    // PUSHBUTTON "OK", 1, 10, 20, 30, 14
    data.extend_from_slice(&0x5001_0000u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&10i16.to_le_bytes());
    data.extend_from_slice(&20i16.to_le_bytes());
    data.extend_from_slice(&30i16.to_le_bytes());
    data.extend_from_slice(&14i16.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes());
    data.extend_from_slice(&0x0080u16.to_le_bytes());
    data.extend_from_slice(&utf16le("OK"));
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    align_dword(&mut data);

    // LTEXT "Hi", -1 (65535), 5, 5, 20, 10
    data.extend_from_slice(&0x5002_0000u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&5i16.to_le_bytes());
    data.extend_from_slice(&5i16.to_le_bytes());
    data.extend_from_slice(&20i16.to_le_bytes());
    data.extend_from_slice(&10i16.to_le_bytes());
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // id = -1
    data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // class marker
    data.extend_from_slice(&0x0082u16.to_le_bytes()); // STATIC
    data.extend_from_slice(&utf16le("Hi"));
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    align_dword(&mut data);

    // EDITTEXT 2, 0, 30, 40, 10 — last control, no trailing in-payload
    // pad (the .res record-level pad covers it).
    data.extend_from_slice(&0x5081_0000u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0i16.to_le_bytes());
    data.extend_from_slice(&30i16.to_le_bytes());
    data.extend_from_slice(&40i16.to_le_bytes());
    data.extend_from_slice(&10i16.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes()); // id
    data.extend_from_slice(&0xFFFFu16.to_le_bytes());
    data.extend_from_slice(&0x0081u16.to_le_bytes()); // EDIT
    data.extend_from_slice(&0u16.to_le_bytes()); // empty title
    data.extend_from_slice(&0u16.to_le_bytes()); // creationDataLen

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_dialog_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G5a-5: DIALOG + STRINGTABLE coexist. brc32-observed type-internal
/// order with DIALOG present: MENU(4) → DIALOG(5) → ACCEL(9) →
/// STRINGTABLE(6). With only DIALOG+STRINGTABLE that reduces to
/// DIALOG(5) → STRINGTABLE(6). This pins the order so a future
/// refactor cannot silently invert it.
#[test]
fn g5a_dialog_and_stringtable_coexist() {
    let src = include_str!("corpus/rc/dialog_with_stringtable.rc");

    // DIALOG payload first.
    let mut dlg_data = Vec::new();
    dlg_data.extend_from_slice(&0x8088_0000u32.to_le_bytes());
    dlg_data.extend_from_slice(&0u32.to_le_bytes()); // ex_style
    dlg_data.extend_from_slice(&0u16.to_le_bytes()); // cdit
    dlg_data.extend_from_slice(&0i16.to_le_bytes());
    dlg_data.extend_from_slice(&0i16.to_le_bytes());
    dlg_data.extend_from_slice(&100i16.to_le_bytes());
    dlg_data.extend_from_slice(&50i16.to_le_bytes());
    dlg_data.extend_from_slice(&0u16.to_le_bytes()); // menu
    dlg_data.extend_from_slice(&0u16.to_le_bytes()); // class
    dlg_data.extend_from_slice(&0u16.to_le_bytes()); // title empty
    align_dword(&mut dlg_data);

    // STRINGTABLE second.
    let str_data = bundle_data(&[(1, "hello")]);

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_dialog_record(&mut golden, 100, dlg_data);
    let hdr = res_hdr_typed(
        str_data.len() as u32,
        6, // RT_STRING
        1, // bundle_id
        FLAGS_DEFAULT,
        LANG_DEFAULT,
    );
    golden.extend_from_slice(&hdr);
    golden.extend_from_slice(&str_data);
    pad_to_dword(&mut golden);
    compare(src, src.as_bytes(), &golden);
}

/// G-fix-1 / MAJOR-1: MENUITEM trailing MF_* flag identifiers (GRAYED,
/// INACTIVE, CHECKED, MENUBARBREAK, MENUBREAK, HELP) — byte-exact
/// differential against brc32 5.40 for the full corpus fixture. This
/// pins the parser-resolved flag bits AND the writer's OR-with-MF_END
/// behaviour, the path the Phase G review's MAJOR-1 caught silently
/// dropping the flag bits.
#[test]
fn g_fix_1_menu_flags() {
    let src = include_str!("corpus/rc/menu_flags.rc");
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]); // MenuHeader: wVersion=0, wOffset=0
    // 7 items total. brc32 sets MF_END (0x80) on the last sibling and
    // OR's the source-level MF_* bits onto every item.
    push_item(&mut data, 0x0001, 200, "A"); // GRAYED
    push_item(&mut data, 0x0008, 201, "B"); // CHECKED
    push_item(&mut data, 0x0003, 202, "C"); // GRAYED|INACTIVE
    push_item(&mut data, 0x0020, 203, "D"); // MENUBARBREAK
    push_item(&mut data, 0x0040, 204, "E"); // MENUBREAK
    push_item(&mut data, 0x4000, 205, "F"); // HELP
    push_item(&mut data, 0x0083, 206, "G"); // GRAYED|INACTIVE|MF_END
    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_menu_record(&mut golden, 100, data);
    compare(src, src.as_bytes(), &golden);
}

/// G4-7: MENU + STRINGTABLE coexist. brc32-observed type-internal order:
/// MENU (type 4) is emitted BEFORE STRINGTABLE (type 6) in the .res
/// file, regardless of source order. This test pins the order so a
/// future refactor cannot silently invert it.
#[test]
fn g4_menu_and_stringtable_coexist() {
    let src = include_str!("corpus/rc/menu_string.rc");
    // MENU first.
    let mut menu_data = Vec::new();
    menu_data.extend_from_slice(&[0, 0, 0, 0]);
    push_popup(&mut menu_data, 0x0090, "File");
    push_item(&mut menu_data, 0x0080, 200, "Exit");
    // STRINGTABLE second.
    let str_data = bundle_data(&[(1, "hello")]);

    let mut golden = Vec::new();
    golden.extend_from_slice(&NULL_HEADER);
    push_menu_record(&mut golden, 100, menu_data);
    // STRINGTABLE record with bundle_id=1 (since id=1 -> bundle 1).
    let hdr = res_hdr_typed(
        str_data.len() as u32,
        6, // RT_STRING
        1, // bundle_id
        FLAGS_DEFAULT,
        LANG_DEFAULT,
    );
    golden.extend_from_slice(&hdr);
    golden.extend_from_slice(&str_data);
    pad_to_dword(&mut golden);

    compare(src, src.as_bytes(), &golden);
}
