//! Phase G / G3 — PE `.rsrc` section structural tests.
//!
//! Verifies that:
//! 1. **O1 byte-identical guard** — a TU with no `.rc` sibling produces a
//!    PE byte-identical to a TU compiled the old (no-rsrc) way. This is the
//!    central leave-it-green contract: the 88-program e2e corpus must stay
//!    byte-for-byte unchanged.
//! 2. With a single STRINGTABLE the produced PE gains a fifth `.rsrc`
//!    section after `.data`; `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE
//!    = 2]` is non-zero and matches `.rsrc`'s VirtualAddress / VirtualSize;
//!    the three-level resource directory parses to one RT_STRING type with
//!    one bundle whose leaf points (RVA-wise) at the bundle data.
//! 3. Multiple bundles (IDs across `id >> 4` boundaries) yield multiple
//!    type-level → bundle-level entries, sorted ascending.
//! 4. Hand-rolled byte oracle for a known small input: every byte of the
//!    `.rsrc` section, computed by hand from the Win32 spec, must equal
//!    what mdbcc emits. Complementary precision oracle next to the
//!    structural tests above.
//!
//! Structural, in-process, no external toolchain (mirrors
//! `tests/pe_imports.rs` / `tests/pe_layout.rs`).

#![cfg(windows)]

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_pe_with_rc;
use mdbcc::compile::{compile_to_object_with, compile_to_object_with_target};
use mdbcc::compile_to_pe;
use mdbcc::link::pe_writer::build_rsrc;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;
use mdbcc::rc;

const PE_OFF: usize = 0x80;
const SECT_HDR_LEN: usize = 40;

fn parse_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn parse_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// COFF `NumberOfSections`.
fn num_sections(pe: &[u8]) -> u16 {
    parse_u16(pe, PE_OFF + 4 + 2)
}

/// `(raw_ptr, raw_size, vsize, va)` for the section named `name`.
fn section(pe: &[u8], name: &[u8]) -> Option<(usize, usize, u32, u32)> {
    let nsec = num_sections(pe) as usize;
    let sizeof_opt = parse_u16(pe, PE_OFF + 4 + 16) as usize;
    let tbl = PE_OFF + 4 + 20 + sizeof_opt;
    for i in 0..nsec {
        let h = tbl + i * SECT_HDR_LEN;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        if pe[h..h + 8] == want {
            return Some((
                parse_u32(pe, h + 20) as usize, // PointerToRawData
                parse_u32(pe, h + 16) as usize, // SizeOfRawData
                parse_u32(pe, h + 8),           // VirtualSize
                parse_u32(pe, h + 12),          // VirtualAddress
            ));
        }
    }
    None
}

/// `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE = 2]`: (rva, size).
fn data_dir_resource(pe: &[u8]) -> (u32, u32) {
    let opt = PE_OFF + 4 + 20;
    let magic = parse_u16(pe, opt);
    let dd_base = if magic == 0x10B { 96 } else { 112 };
    let rva = parse_u32(pe, opt + dd_base + 2 * 8);
    let size = parse_u32(pe, opt + dd_base + 2 * 8 + 4);
    (rva, size)
}

/// The trivial console program used by every test in this file — a
/// `printf`-less `main` so mdbcc emits the smallest possible PE. Phase G3
/// is **independent** of the host TU's contents; the only thing that
/// matters is the presence/absence of the `RcUnit` argument.
const PROG_TRIVIAL: &str = "int main(void) { return 0; }";

/// A representative `.rc` source: one STRINGTABLE with a single entry. The
/// `.rc` parser (G1) already handles this exact shape; the `.res` writer
/// (G2) byte-differentials it against brc32 in `tests/rc_res.rs`. Here we
/// only care about the PE-side wiring (G3).
const RC_ONE_ENTRY: &str = "STRINGTABLE\nBEGIN\n    1 \"hello\"\nEND\n";

/// A `.rc` that spans two bundles: `id=1` is in bundle 1 (`(1 >> 4) + 1`),
/// `id=17` is in bundle 2 (`(17 >> 4) + 1`).
const RC_TWO_BUNDLES: &str = "STRINGTABLE\nBEGIN\n    1 \"a\"\n    17 \"b\"\nEND\n";

/// Compile a source string with no `.rc` sibling — equivalent to
/// [`mdbcc::compile_to_pe`] but routed through the explicit
/// [`compile_to_pe_with_rc`] entry so we exercise the same code path the
/// `Some` tests use, just with `None`.
fn compile_no_rc(src: &str) -> Vec<u8> {
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    compile_to_pe_with_rc(src.as_bytes(), "<input>", &resolver, None).expect("compile ok")
}

/// Compile a source string with a parsed `RcUnit`.
fn compile_with_rc(src: &str, rc_src: &str) -> Vec<u8> {
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let unit = rc::parse(rc_src).expect("rc parse ok");
    compile_to_pe_with_rc(src.as_bytes(), "<input>", &resolver, Some(&unit)).expect("compile ok")
}

// ---------------------------------------------------------------------------
// Test 1: O1 byte-identical guard — the leave-it-green contract
// ---------------------------------------------------------------------------

/// Producing a PE for a TU that has **no** `.rc` sibling must yield the same
/// bytes as the pre-G3 writer. The `compile_to_pe` no-path entry point is
/// the route the 88-program e2e corpus uses; this test pins that the
/// `compile_to_pe_with_rc(..., None)` path is byte-equivalent (so the
/// `Option::None` short-circuit holds at every layer). Section count
/// stays 4; `DataDirectory[2]` stays zero.
#[test]
fn no_rc_pe_is_byte_identical_to_legacy_compile_to_pe() {
    let legacy = compile_to_pe(PROG_TRIVIAL.as_bytes()).expect("compile_to_pe ok");
    let new = compile_no_rc(PROG_TRIVIAL);
    assert_eq!(
        legacy, new,
        "compile_to_pe_with_rc(..., None) must produce a byte-identical \
         image to the legacy compile_to_pe — this is the O1 leave-it-green \
         contract (the 88-program e2e corpus depends on this byte equality)"
    );
    assert_eq!(
        num_sections(&new),
        4,
        "a TU without resources must keep NumberOfSections == 4 (the \
         resource path is gated on `Some(unit)`; this proves the gate)"
    );
    assert_eq!(
        data_dir_resource(&new),
        (0, 0),
        "DataDirectory[2] must be zero for a TU without resources"
    );
    assert!(
        section(&new, b".rsrc").is_none(),
        "no `.rsrc` section may appear when no `.rc` sibling exists"
    );
}

// ---------------------------------------------------------------------------
// Test 2: single STRINGTABLE — `.rsrc` appears, dir[2] points at it, the
//         three-level tree parses and the leaf RVA hits the bundle data.
// ---------------------------------------------------------------------------

#[test]
fn single_stringtable_emits_rsrc_section_with_dir2_filled() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_ONE_ENTRY);

    // The fifth section is `.rsrc`.
    assert_eq!(num_sections(&pe), 5, "NumberOfSections must grow to 5");
    let (rsrc_ptr, _rsrc_raw, rsrc_vsize, rsrc_va) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");

    // DataDirectory[2] matches the section's VirtualAddress / VirtualSize.
    let (dd_rva, dd_size) = data_dir_resource(&pe);
    assert_eq!(
        dd_rva, rsrc_va,
        "DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress \
         must equal the .rsrc section's VirtualAddress"
    );
    assert_eq!(
        dd_size, rsrc_vsize,
        "DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size must equal \
         the .rsrc section's VirtualSize"
    );

    // Parse the three-level resource tree.
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];

    // ROOT directory header: NumberOfNamedEntries=0, NumberOfIdEntries=1.
    assert_eq!(parse_u16(rsrc, 12), 0, "ROOT.NumberOfNamedEntries");
    assert_eq!(
        parse_u16(rsrc, 14),
        1,
        "ROOT.NumberOfIdEntries (RT_STRING only)"
    );

    // ROOT entry: Name=RT_STRING(6), OffsetToData top-bit-set -> subdir.
    let root_entry_off = 16;
    assert_eq!(
        parse_u32(rsrc, root_entry_off),
        6,
        "ROOT entry Name = RT_STRING"
    );
    let type_dir_field = parse_u32(rsrc, root_entry_off + 4);
    assert!(
        type_dir_field & 0x8000_0000 != 0,
        "ROOT.OffsetToData top bit must be set (points to TYPE subdir)"
    );
    let type_dir_off = (type_dir_field & 0x7FFF_FFFF) as usize;

    // TYPE directory header: one bundle entry.
    assert_eq!(
        parse_u16(rsrc, type_dir_off + 14),
        1,
        "TYPE.NumberOfIdEntries"
    );

    // TYPE entry: Name = bundle_id 1 (since `id=1` -> bundle `(1>>4)+1 = 1`).
    let bundle_entry_off = type_dir_off + 16;
    assert_eq!(parse_u32(rsrc, bundle_entry_off), 1, "bundle_id == 1");
    let bundle_dir_field = parse_u32(rsrc, bundle_entry_off + 4);
    assert!(bundle_dir_field & 0x8000_0000 != 0, "TYPE entry top bit");
    let bundle_dir_off = (bundle_dir_field & 0x7FFF_FFFF) as usize;

    // BUNDLE directory header: one Language entry.
    assert_eq!(
        parse_u16(rsrc, bundle_dir_off + 14),
        1,
        "BUNDLE.NumberOfIdEntries"
    );

    // LANGUAGE entry: Name = language id, OffsetToData top-bit-CLEAR -> leaf.
    let lang_entry_off = bundle_dir_off + 16;
    assert_eq!(
        parse_u32(rsrc, lang_entry_off),
        0x0809,
        "default language id = 0x0809 (en-GB; the brc32 default)"
    );
    let leaf_field = parse_u32(rsrc, lang_entry_off + 4);
    assert!(
        leaf_field & 0x8000_0000 == 0,
        "LANGUAGE entry top bit must be CLEAR (points to a data-entry leaf)"
    );
    let leaf_off = leaf_field as usize;

    // IMAGE_RESOURCE_DATA_ENTRY leaf: OffsetToData is an RVA (relative to
    // ImageBase), Size is the bundle size in bytes.
    let leaf_rva = parse_u32(rsrc, leaf_off);
    let leaf_size = parse_u32(rsrc, leaf_off + 4);
    let leaf_codepage = parse_u32(rsrc, leaf_off + 8);
    assert_eq!(leaf_codepage, 0, "leaf CodePage = 0 (neutral)");

    // The bundle data lies inside the `.rsrc` section: leaf_rva must
    // resolve to a valid offset within the section.
    assert!(
        leaf_rva >= rsrc_va && leaf_rva + leaf_size <= rsrc_va + rsrc_vsize,
        "leaf data RVA must point inside the .rsrc section: \
         leaf_rva={leaf_rva:#x}, leaf_size={leaf_size}, \
         section [{rsrc_va:#x}, {:#x})",
        rsrc_va + rsrc_vsize
    );

    // The 16-slot bundle for "hello" at id=1 (slot=1):
    //   slot 0: len=0 (one u16 = 2 bytes)
    //   slot 1: len=5, then 'h','e','l','l','o' as UTF-16LE (12 bytes)
    //   slots 2..=15: each len=0 (28 bytes)
    // Total = 2 + 12 + 28 = 42 bytes.
    assert_eq!(
        leaf_size, 42,
        "bundle size = 16 slots, one populated with \"hello\""
    );

    // The "hello" bytes should appear UTF-16LE-encoded at the leaf RVA.
    let leaf_file_off = rsrc_ptr + (leaf_rva - rsrc_va) as usize;
    let bundle_bytes = &pe[leaf_file_off..leaf_file_off + leaf_size as usize];
    // slot 0 = u16 0
    assert_eq!(&bundle_bytes[0..2], &[0u8, 0]);
    // slot 1: u16 len = 5, then 'h','e','l','l','o' as UTF-16LE
    assert_eq!(&bundle_bytes[2..4], &5u16.to_le_bytes());
    assert_eq!(
        &bundle_bytes[4..14],
        &[b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]
    );
}

// ---------------------------------------------------------------------------
// Test 3: multiple bundles → multiple type-level→bundle-level entries,
//         sorted ascending.
// ---------------------------------------------------------------------------

#[test]
fn multiple_bundles_yield_multiple_sorted_entries() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_TWO_BUNDLES);
    let (rsrc_ptr, _, rsrc_vsize, _) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];

    // ROOT still has just one type (RT_STRING).
    assert_eq!(parse_u16(rsrc, 14), 1, "ROOT.NumberOfIdEntries");

    // Resolve the TYPE directory's offset.
    let type_dir_field = parse_u32(rsrc, 16 + 4);
    let type_dir_off = (type_dir_field & 0x7FFF_FFFF) as usize;

    // TYPE directory now has TWO bundle entries.
    assert_eq!(
        parse_u16(rsrc, type_dir_off + 14),
        2,
        "TYPE.NumberOfIdEntries must equal 2 for two bundles"
    );

    // The bundle entries must be sorted ascending by Name (bundle id).
    let entry0_name = parse_u32(rsrc, type_dir_off + 16);
    let entry1_name = parse_u32(rsrc, type_dir_off + 16 + 8);
    assert_eq!(entry0_name, 1, "first bundle id = 1 (id=1 -> bundle 1)");
    assert_eq!(entry1_name, 2, "second bundle id = 2 (id=17 -> bundle 2)");
    assert!(
        entry0_name < entry1_name,
        "bundle entries must be sorted ascending (Win32 directory contract)"
    );
}

// ---------------------------------------------------------------------------
// Test 4: hand-rolled byte oracle — every byte of a known small `.rsrc`
// ---------------------------------------------------------------------------

/// Compute by hand the expected `.rsrc` bytes for the simplest non-trivial
/// input: one STRINGTABLE entry, id=1, value="hi". The test passes the
/// same section-base-RVA mdbcc would compute and asserts every byte.
#[test]
fn build_rsrc_byte_exact_for_one_entry_hi() {
    let unit = rc::parse("STRINGTABLE\nBEGIN\n    1 \"hi\"\nEND\n").unwrap();

    // Pick an arbitrary section base RVA (the test is base-RVA agnostic;
    // every offset inside the section is section-relative; the leaf RVA
    // is `sect_base_rva + leaf_payload_offset`).
    let base: u32 = 0x5000;
    let bytes = build_rsrc(&unit, base);

    // Layout (one bundle, one language):
    //   0x00 ROOT dir (16 B): {0,0,0,0,0,1}
    //   0x10 ROOT entry: Name=RT_STRING=6, Off=SUBDIR|0x18
    //   0x18 TYPE dir (16 B): {0,0,0,0,0,1}
    //   0x28 TYPE entry: Name=bundle_id=1, Off=SUBDIR|0x30
    //   0x30 BUNDLE dir (16 B): {0,0,0,0,0,1}
    //   0x40 LANGUAGE entry: Name=0x0809, Off=0x48 (no top bit)
    //   0x48 DATA_ENTRY (16 B): {RVA=base+0x58, Size=36, 0, 0}
    //   0x58 bundle data: 16 slots, slot 0 len=0; slot 1 len=2 + "hi"
    //                     UTF-16LE; slots 2..=15 len=0
    //                     = 2 + (2+4) + 14*2 = 2 + 6 + 28 = 36 bytes
    //   total = 0x58 + 36 = 0x7C = 124 bytes (no trailing alignment
    //   needed — already DWORD-aligned).
    let mut expected = Vec::new();

    // ROOT directory: 4+4+2+2+2+2
    expected.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    expected.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    expected.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    expected.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    expected.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
    expected.extend_from_slice(&1u16.to_le_bytes()); // NumberOfIdEntries

    // ROOT entry: type=RT_STRING, subdir at 0x18
    expected.extend_from_slice(&6u32.to_le_bytes());
    expected.extend_from_slice(&(0x8000_0000u32 | 0x18).to_le_bytes());

    // TYPE directory at 0x18
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&1u16.to_le_bytes());

    // TYPE entry: bundle_id=1, subdir at 0x30
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&(0x8000_0000u32 | 0x30).to_le_bytes());

    // BUNDLE directory at 0x30
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&1u16.to_le_bytes());

    // LANGUAGE entry: lang=0x0809 (default), leaf at 0x48 (top bit clear)
    expected.extend_from_slice(&0x0809u32.to_le_bytes());
    expected.extend_from_slice(&0x48u32.to_le_bytes());

    // DATA_ENTRY at 0x48: payload RVA = base + 0x58, size = 36, codepage 0,
    // reserved 0.
    expected.extend_from_slice(&(base + 0x58).to_le_bytes());
    expected.extend_from_slice(&36u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());

    // Bundle data at 0x58: 16 slots, slot 0 empty, slot 1 = "hi", slots
    // 2..=15 empty.
    expected.extend_from_slice(&0u16.to_le_bytes()); // slot 0
    expected.extend_from_slice(&2u16.to_le_bytes()); // slot 1 len = 2
    expected.extend_from_slice(&b'h'.to_le_bytes());
    expected.push(0); // UTF-16LE
    expected.extend_from_slice(&b'i'.to_le_bytes());
    expected.push(0); // UTF-16LE
    for _ in 2..16 {
        expected.extend_from_slice(&0u16.to_le_bytes()); // empty slot
    }

    assert_eq!(
        bytes, expected,
        "build_rsrc must produce the exact hand-computed Win32 resource \
         tree for a STRINGTABLE with one entry id=1 \"hi\""
    );
}

// ---------------------------------------------------------------------------
// G4 — multi-type `.rsrc` (MENU / STRINGTABLE / ACCELERATORS together)
// ---------------------------------------------------------------------------
//
// G4 generalises the directory tree to multiple type-level entries
// (RT_MENU=4, RT_STRING=6, RT_ACCELERATOR=9). Types must come out sorted
// ascending in ROOT (Win32 contract — id entries are numerically sorted).
// The three structural tests below pin the type-level entries when the
// unit carries one MENU, MENU+STRINGTABLE, then MENU+STRINGTABLE+ACCEL.

const RC_ONE_MENU: &str =
    "100 MENU\nBEGIN\n  POPUP \"File\"\n  BEGIN\n    MENUITEM \"Exit\", 200\n  END\nEND\n";

const RC_MENU_AND_STRING: &str = "\
100 MENU\nBEGIN\n  POPUP \"File\"\n  BEGIN\n    MENUITEM \"Exit\", 200\n  END\nEND\n\
\nSTRINGTABLE\nBEGIN\n    1 \"hello\"\nEND\n";

const RC_MENU_STRING_ACCEL: &str = "\
100 MENU\nBEGIN\n  POPUP \"File\"\n  BEGIN\n    MENUITEM \"Exit\", 200\n  END\nEND\n\
\nSTRINGTABLE\nBEGIN\n    1 \"hello\"\nEND\n\
\n100 ACCELERATORS\nBEGIN\n  \"S\", 200, VIRTKEY, CONTROL\nEND\n";

/// Read the ROOT directory's set of type-level id entries (Names),
/// sorted in directory order (which Win32 mandates be ascending).
fn root_type_ids(rsrc: &[u8]) -> Vec<u32> {
    let n_ids = parse_u16(rsrc, 14) as usize;
    (0..n_ids).map(|i| parse_u32(rsrc, 16 + i * 8)).collect()
}

fn read_resource_name(rsrc: &[u8], off: usize) -> String {
    let len = parse_u16(rsrc, off) as usize;
    let mut units = Vec::with_capacity(len);
    for i in 0..len {
        units.push(parse_u16(rsrc, off + 2 + i * 2));
    }
    String::from_utf16(&units).expect("valid UTF-16 resource name")
}

/// G4-R1: A `.rc` with only a MENU emits `.rsrc` with a single RT_MENU
/// type-level entry (type=4), and no RT_STRING/RT_ACCELERATOR entries.
#[test]
fn g4_pe_rsrc_only_menu() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_ONE_MENU);
    assert_eq!(num_sections(&pe), 5, ".rsrc section must be present");
    let (rsrc_ptr, _, rsrc_vsize, _) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];
    let types = root_type_ids(rsrc);
    assert_eq!(
        types,
        vec![4],
        "a MENU-only `.rc` must yield exactly one ROOT entry: RT_MENU(4); \
         got {types:?}"
    );
}

/// G4-R2: A `.rc` with MENU + STRINGTABLE emits both RT_MENU (4) and
/// RT_STRING (6) type-level entries, sorted ascending (4 then 6).
#[test]
fn g4_pe_rsrc_menu_and_stringtable_sorted() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_MENU_AND_STRING);
    let (rsrc_ptr, _, rsrc_vsize, _) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];
    let types = root_type_ids(rsrc);
    assert_eq!(
        types,
        vec![4, 6],
        "MENU+STRINGTABLE must yield two ROOT entries sorted ascending: \
         RT_MENU(4), RT_STRING(6); got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// G5a — DIALOG in PE `.rsrc`
// ---------------------------------------------------------------------------

const RC_ONE_DIALOG: &str = "100 DIALOG 0, 0, 100, 50\nBEGIN\nEND\n";

const RC_DIALOG_STRING_MENU: &str = "\
100 DIALOG 0, 0, 100, 50\nBEGIN\nEND\n\
\nSTRINGTABLE\nBEGIN\n    1 \"hello\"\nEND\n\
\n100 MENU\nBEGIN\n  POPUP \"File\"\n  BEGIN\n    MENUITEM \"Exit\", 200\n  END\nEND\n";

/// G5a-R1: A `.rc` with only a DIALOG emits `.rsrc` with a single
/// RT_DIALOG type-level entry (type=5).
#[test]
fn g5a_pe_rsrc_only_dialog() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_ONE_DIALOG);
    assert_eq!(num_sections(&pe), 5, ".rsrc section must be present");
    let (rsrc_ptr, _, rsrc_vsize, _) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];
    let types = root_type_ids(rsrc);
    assert_eq!(
        types,
        vec![5],
        "a DIALOG-only `.rc` must yield exactly one ROOT entry: RT_DIALOG(5); \
         got {types:?}"
    );
}

/// G5a-R2: A `.rc` with DIALOG + STRINGTABLE + MENU emits all three
/// type-level entries (4, 5, 6) sorted ascending. Pins the ROOT-level
/// sort with DIALOG inserted between MENU and STRINGTABLE.
#[test]
fn g5a_pe_rsrc_menu_dialog_string_sorted_ascending() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_DIALOG_STRING_MENU);
    let (rsrc_ptr, _, rsrc_vsize, _) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];
    let types = root_type_ids(rsrc);
    assert_eq!(
        types,
        vec![4, 5, 6],
        "MENU+DIALOG+STRINGTABLE must yield three ROOT entries sorted \
         ascending: RT_MENU(4), RT_DIALOG(5), RT_STRING(6); got {types:?}"
    );
}

/// G4-R3: A `.rc` with MENU + STRINGTABLE + ACCELERATORS emits all
/// three type-level entries (4, 6, 9) sorted ascending.
#[test]
fn g4_pe_rsrc_menu_string_accel_all_three() {
    let pe = compile_with_rc(PROG_TRIVIAL, RC_MENU_STRING_ACCEL);
    let (rsrc_ptr, _, rsrc_vsize, _) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];
    let types = root_type_ids(rsrc);
    assert_eq!(
        types,
        vec![4, 6, 9],
        "MENU+STRINGTABLE+ACCELERATORS must yield three ROOT entries \
         sorted ascending: RT_MENU(4), RT_STRING(6), RT_ACCELERATOR(9); \
         got {types:?}"
    );

    // Each type's directory must point at a valid sub-tree. Drill into
    // the RT_MENU entry and verify it has a single MENU id (100), with
    // a single LANGUAGE leaf whose RVA lies inside the section.
    let (_, _, rsrc_vsize, rsrc_va) = section(&pe, b".rsrc").expect(".rsrc section");
    let menu_entry_off = 16; // first ROOT id entry
    let menu_subdir = parse_u32(rsrc, menu_entry_off + 4) & 0x7FFF_FFFF;
    // TYPE directory at `menu_subdir` must have exactly one id entry (id=100).
    let menu_n_ids = parse_u16(rsrc, menu_subdir as usize + 14);
    assert_eq!(menu_n_ids, 1, "RT_MENU TYPE dir must have one id entry");
    let menu_id = parse_u32(rsrc, menu_subdir as usize + 16);
    assert_eq!(menu_id, 100, "MENU id must be 100");
    // Drill into the NAME subdir → LANGUAGE leaf.
    let name_subdir = parse_u32(rsrc, menu_subdir as usize + 20) & 0x7FFF_FFFF;
    let lang_n_ids = parse_u16(rsrc, name_subdir as usize + 14);
    assert_eq!(lang_n_ids, 1, "MENU NAME dir must have one language");
    let leaf_off = parse_u32(rsrc, name_subdir as usize + 20) as usize;
    let leaf_rva = parse_u32(rsrc, leaf_off);
    let leaf_size = parse_u32(rsrc, leaf_off + 4);
    assert!(
        leaf_rva >= rsrc_va && leaf_rva + leaf_size <= rsrc_va + rsrc_vsize,
        "MENU leaf RVA must point inside .rsrc"
    );
}

#[test]
fn named_menu_uses_resource_name_string_entry() {
    let unit = rc::parse(
        "MAIN_MENU MENU\nBEGIN\n  POPUP \"File\"\n  BEGIN\n    MENUITEM \"Exit\", 200\n  END\nEND\n",
    )
    .unwrap();
    let base = 0x5000;
    let rsrc = build_rsrc(&unit, base);

    assert_eq!(parse_u16(&rsrc, 12), 0, "ROOT.NumberOfNamedEntries");
    assert_eq!(parse_u16(&rsrc, 14), 1, "ROOT.NumberOfIdEntries");
    assert_eq!(parse_u32(&rsrc, 16), 4, "ROOT type = RT_MENU");
    let type_dir_off = (parse_u32(&rsrc, 20) & 0x7FFF_FFFF) as usize;

    assert_eq!(
        parse_u16(&rsrc, type_dir_off + 12),
        1,
        "RT_MENU TYPE.NumberOfNamedEntries"
    );
    assert_eq!(
        parse_u16(&rsrc, type_dir_off + 14),
        0,
        "RT_MENU TYPE.NumberOfIdEntries"
    );
    let name_field = parse_u32(&rsrc, type_dir_off + 16);
    assert!(
        name_field & 0x8000_0000 != 0,
        "named resource entry must use the high-bit string offset form"
    );
    let name_off = (name_field & 0x7FFF_FFFF) as usize;
    assert_eq!(read_resource_name(&rsrc, name_off), "MAIN_MENU");

    let menu_dir_off = (parse_u32(&rsrc, type_dir_off + 20) & 0x7FFF_FFFF) as usize;
    assert_eq!(
        parse_u16(&rsrc, menu_dir_off + 14),
        1,
        "named MENU directory must have one language"
    );
    let leaf_off = parse_u32(&rsrc, menu_dir_off + 20) as usize;
    let leaf_rva = parse_u32(&rsrc, leaf_off);
    let leaf_size = parse_u32(&rsrc, leaf_off + 4);
    assert!(
        leaf_rva >= base && leaf_rva + leaf_size <= base + rsrc.len() as u32,
        "named MENU leaf must point inside the .rsrc payload"
    );
}

#[test]
fn link_input_res_file_appends_rsrc_section() {
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let obj = compile_to_object_with(PROG_TRIVIAL.as_bytes(), "main.c", &resolver)
        .expect("compile main object");
    let unit = rc::parse(RC_ONE_ENTRY).expect("parse rc");
    let res = rc::write_res(&unit);
    let opts = LinkOpts {
        subsystem: Subsystem::Console,
        ..LinkOpts::default()
    };

    let pe = link::link(
        &[
            Input::Object(&obj),
            Input::ResFile {
                name: "app.res".into(),
                bytes: res,
            },
        ],
        &opts,
    )
    .expect("link with .res");

    assert_eq!(num_sections(&pe), 5, "NumberOfSections must grow to 5");
    let (rsrc_ptr, _, rsrc_vsize, rsrc_va) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    assert_eq!(
        data_dir_resource(&pe),
        (rsrc_va, rsrc_vsize),
        "DataDirectory[2] must point at the appended .rsrc section"
    );
    let rsrc = &pe[rsrc_ptr..rsrc_ptr + rsrc_vsize as usize];
    assert_eq!(
        root_type_ids(rsrc),
        vec![6],
        "linked .res must emit RT_STRING"
    );
}

#[test]
fn link_i386_input_res_file_patches_pe32_resource_directory() {
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let obj = compile_to_object_with_target(
        PROG_TRIVIAL.as_bytes(),
        "main.c",
        &resolver,
        TargetKind::Win32,
    )
    .expect("compile i386 main object");
    let unit = rc::parse(RC_ONE_ENTRY).expect("parse rc");
    let res = rc::write_res(&unit);
    let opts = LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    };

    let pe = link::link(
        &[
            Input::Object(&obj),
            Input::ResFile {
                name: "app.res".into(),
                bytes: res,
            },
        ],
        &opts,
    )
    .expect("link i386 with .res");

    let opt = PE_OFF + 4 + 20;
    assert_eq!(parse_u16(&pe, opt), 0x10B, "i386 link must emit PE32");
    let (_rsrc_ptr, _, rsrc_vsize, rsrc_va) =
        section(&pe, b".rsrc").expect(".rsrc section must be present");
    assert_eq!(
        data_dir_resource(&pe),
        (rsrc_va, rsrc_vsize),
        "PE32 DataDirectory[2] must point at .rsrc"
    );

    let cert_dir_off = opt + 96 + 4 * 8;
    assert_eq!(
        (
            parse_u32(&pe, cert_dir_off),
            parse_u32(&pe, cert_dir_off + 4)
        ),
        (0, 0),
        "PE32 Certificate Table directory must not be overwritten by .rsrc"
    );
}
