//! Regression oracle for the PE section-layout fix.
//!
//! The PE writer historically pinned section RVAs at fixed 4 KB spacing, so
//! any program whose `.text` (or any section) exceeded 0x1000 bytes produced
//! an image with overlapping virtual ranges — an invalid PE that Windows
//! refuses to load (`STATUS_INVALID_IMAGE_FORMAT`). This test builds a
//! program with a deliberately large `.text` that *also* exercises `.idata`
//! (an imported `printf` call) and `.rdata` (a string literal) emitted after
//! the bloated code, then asserts the produced exe both *loads on Windows*
//! and prints the *exact* Rust-computed result. In-process like O1
//! (`tests/printf_format.rs`): no external toolchain.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);
impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build `src` with mdbcc, write the PE to a temp `.exe`, run it, and return
/// `(stdout, exit_code)`. A failure to *launch* (the unloadable-exe defect)
/// surfaces as a panic in `.expect("launch")`, exactly the RED we want.
fn run(src: &str) -> (String, i32) {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_pl_{}_{}.exe", std::process::id(), n));
    let tmp = TempExe(p);
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let o = Command::new(&tmp.0).output().expect("launch");
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        o.status.code().expect("exit code"),
    )
}

/// Number of trivial functions to emit. Each compiles to a non-trivial body;
/// with this many, `.text` comfortably exceeds 8 KB (the old 4 KB ceiling
/// gave overlapping `.text`/`.idata` virtual ranges → unloadable exe).
const NFUNC: i64 = 800;

/// The per-function pure value, computed identically in Rust and in the
/// generated C so the assertion is exact. Only `*`, `+`, `%` (all confirmed
/// in mdbcc's C subset, see `tests/corpus/portable/arith.c`).
fn fval(i: i64) -> i64 {
    (i * 7 + 3) % 97
}

/// Marker text for the file-scope `char *` global. Its bytes land in
/// `.rdata`; the global's 8-byte slot in `.data` holds the *absolute*
/// address `IMAGE_BASE + rdata_rva + off` — the binary's only
/// non-relocated absolute pointer (no `.reloc` safety net). Asserting
/// these exact bytes after a >8 KB `.text` catches a stale `rdata_rva`
/// (the `ptr_str` / `.data` path in the dynamically-shifted regime).
const TAG: &str = "T:";

/// Generate: `NFUNC` trivial functions, a file-scope `char *tag = "T:";`
/// global, then a `main` that sums every call and prints `"%s%d\n"` with
/// `tag` and the sum. This exercises, *after* the large `.text`:
/// `.idata` (printf import), a `.rdata` format string, **and** the
/// `.data` absolute pointer-to-string (`tag`) dereferenced via `%s`.
/// Returns `sum % 256` as the process exit code.
fn big_program() -> (String, i64, i32) {
    let mut src = String::from("#include <stdio.h>\n");
    src.push_str(&format!("char *tag = \"{TAG}\";\n"));
    for i in 0..NFUNC {
        // Body large enough that NFUNC of them blow past 8 KB of .text.
        src.push_str(&format!("int f{i}(void){{ return ({i}*7 + 3) % 97; }}\n"));
    }
    src.push_str("int main(void){\n    int s;\n    s = 0;\n");
    for i in 0..NFUNC {
        src.push_str(&format!("    s += f{i}();\n"));
    }
    // `%s` dereferences the .data absolute pointer `tag` -> a stale/wrong
    // pointer faults or prints garbage, failing the exact-bytes assert.
    src.push_str("    printf(\"%s%d\\n\", tag, s);\n    return s % 256;\n}\n");

    let sum: i64 = (0..NFUNC).map(fval).sum();
    (src, sum, (sum % 256) as i32)
}

// --- Structural large-`.data` lock (mirrors `src/pe.rs`'s header parsing) ---

/// PE offsets, identical to `src/pe.rs`: `e_lfanew` is pinned at `0x80`, the
/// COFF header follows the 4-byte `PE\0\0` signature, the optional header
/// follows the 20-byte COFF header, and `SizeOfOptionalHeader` is `0xF0`
/// (PE32+), so the section table starts at `opt + 0xF0`. Each section header
/// is 40 bytes: VirtualSize at `+8`, VirtualAddress at `+12`, name at `0..8`,
/// Characteristics at `+36`.
const PE_OFF: usize = 0x80;
const SIZEOF_OPT: usize = 0xF0;
const SECT_HDR_LEN: usize = 40;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA` — the bit that distinguishes a real
/// file-image data section from a `.bss`-style zero-fill one.
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;

fn parse_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Find the `(VirtualSize, Characteristics)` of the section named `name`
/// (e.g. `.data`) by reading the produced image's own section table. This
/// inspects the *emitted bytes*, so it cannot be fooled by any optimizer.
fn section(pe: &[u8], name: &[u8]) -> Option<(u32, u32)> {
    let coff = PE_OFF + 4;
    let nsec = u16::from_le_bytes([pe[coff + 2], pe[coff + 3]]) as usize;
    let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
    (0..nsec).find_map(|i| {
        let h = tbl + i * SECT_HDR_LEN;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        if pe[h..h + 8] == want {
            Some((parse_u32(pe, h + 8), parse_u32(pe, h + 36)))
        } else {
            None
        }
    })
}

/// The `bigdata.c` regime — a large *initialized* `.data` section — asserted
/// **structurally**, on the produced PE's own section table, not via stdout.
///
/// WHY THIS IS STRUCTURAL / OPTIMIZER-PROOF: `bigdata.c` proves its regime
/// only transitively, by printing a checksum of a big `static const` array.
/// That checksum is a pure function of compile-time constants, so a
/// constant-folding optimizer — a future `cl`/`bcc32`, or *mdbcc itself* if
/// it ever gains folding (mdbcc is the system under test) — is entitled to
/// fold the loop to a constant and dead-strip the array, shrinking `.data`
/// back below the old ceiling while stdout stays byte-identical and the
/// differential test stays GREEN. The regime would rot silently. This test
/// reads `.data`'s `VirtualSize` directly out of the emitted image, so it
/// fails the instant the array is stripped (VirtualSize collapses below the
/// threshold) regardless of what any present or future optimizer does to the
/// checksum. The achieved size is asserted explicitly so the test cannot
/// silently degrade into a small-`.data` case.
///
/// The size is forced by an *explicit array dimension*
/// (`static const char blob[NBYTES]`), so `.data`'s VirtualSize is a hard,
/// deterministic function of `NBYTES` (the writer emits the whole array into
/// `.data`; trailing bytes past the literal are deterministically zero-filled
/// by `global_image`), not of the literal's length. The program also
/// consumes+prints a checksum so the data is live in source terms too.
const NBYTES: usize = 24_000; // 0x5DC0 — well past the 0x2000 threshold

/// Generate `bigdata.c`'s regime programmatically (no multi-KB literal in
/// this .rs): a file-scope `static const char blob[NBYTES]` initialized from
/// a printable repeating pattern of `lit_len` bytes, plus a `main` that
/// folds all `NBYTES` bytes (literal prefix then zero-fill) into the same
/// `sum*31 + byte` 16-bit rolling checksum `bigdata.c` uses, and prints
/// `len`/`sum`. Returns `(source, expected_stdout)`, the checksum computed
/// in Rust over the identical byte sequence so the assertion is exact.
fn bigdata_program() -> (String, String) {
    // Printable ASCII pattern (no NUL, no `"`/`\`), shorter than NBYTES so
    // the rest of the array is zero-filled — the section size is driven by
    // the explicit `[NBYTES]` dimension, not the literal length.
    const PAT: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-+*=._/#@";
    let lit_len = 4096usize; // < NBYTES; comfortably > C89's 509 minimum
    let mut lit = String::with_capacity(lit_len);
    for k in 0..lit_len {
        lit.push(PAT[k % PAT.len()] as char);
    }

    let mut src = String::from("#include <stdio.h>\n");
    src.push_str(&format!("static const char blob[{NBYTES}] = \"{lit}\";\n"));
    src.push_str("int main(void){\n");
    src.push_str("    unsigned int sum; unsigned int len; unsigned int i;\n");
    src.push_str("    sum = 0u; len = 0u; i = 0u;\n");
    src.push_str(&format!("    while (i < {NBYTES}u) {{\n"));
    src.push_str("        sum = (sum * 31u + (unsigned int)(unsigned char)blob[i]) & 0xFFFFu;\n");
    src.push_str("        len = len + 1u;\n");
    src.push_str("        i = i + 1u;\n");
    src.push_str("    }\n");
    src.push_str("    printf(\"blob len=%u sum=%u\\n\", len, sum);\n");
    src.push_str("    return 0;\n}\n");

    // Rust mirror over the exact byte sequence: pattern for i<lit_len, then
    // 0 for the zero-filled tail up to NBYTES.
    let mut sum: u32 = 0;
    for i in 0..NBYTES {
        let byte = if i < lit_len {
            PAT[i % PAT.len()] as u32
        } else {
            0
        };
        sum = (sum.wrapping_mul(31).wrapping_add(byte)) & 0xFFFF;
    }
    (src, format!("blob len={NBYTES} sum={sum}\n"))
}

#[test]
fn large_data_section_is_structurally_initialized_and_loads() {
    let (src, expected_stdout) = bigdata_program();
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");

    // Structural assertion on the emitted image's own section table.
    let (vsize, chars) = section(&exe, b".data").expect(".data section present");
    assert!(
        vsize > 0x2000,
        "large-.data regime collapsed: .data VirtualSize {vsize:#x} \
         is not > 0x2000 — the big array was (dead-)stripped even though \
         stdout would be unchanged (this is exactly the silent oracle-rot \
         this structural test exists to catch)"
    );
    assert_ne!(
        chars & IMAGE_SCN_CNT_INITIALIZED_DATA,
        0,
        ".data is not flagged CNT_INITIALIZED_DATA (chars={chars:#x}) — \
         the blob must be real file-image bytes, not .bss zero-fill"
    );

    // Load + correctness: the program must still run and print the exact
    // Rust-computed checksum (so the regime is genuinely exercised, not a
    // dead section the loader never validates).
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_pl_bd_{}_{}.exe", std::process::id(), n));
    let tmp = TempExe(p);
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let o = Command::new(&tmp.0).output().expect("launch");
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        expected_stdout,
        "large-.data program loaded but produced wrong stdout"
    );
}

#[test]
fn large_text_section_loads_and_runs() {
    let (src, sum, expected_exit) = big_program();
    // Exact bytes: the `TAG` prefix is the dereference of the `.data`
    // absolute pointer-to-string. If `rdata_rva` is wrong in the
    // large-`.text` regime, this `%s` reads the wrong address ->
    // crash or garbage -> this assert fails (loads-but-wrong-pointer).
    let expected_stdout = format!("{TAG}{sum}\n");

    let (stdout, exit) = run(&src);

    assert_eq!(
        stdout, expected_stdout,
        "large-.text program produced wrong stdout (loaded but miscompiled?)"
    );
    assert_eq!(
        exit, expected_exit,
        "large-.text program produced wrong exit code"
    );
}

/// Read `(MajorOSVersion, MinorOSVersion, MajorSubsystemVersion,
/// MinorSubsystemVersion)` from a PE32+ optional header.
fn version_fields(pe: &[u8]) -> (u16, u16, u16, u16) {
    let opt = PE_OFF + 4 + 20;
    let u16_at = |off: usize| u16::from_le_bytes([pe[opt + off], pe[opt + off + 1]]);
    (u16_at(0x28), u16_at(0x2A), u16_at(0x30), u16_at(0x32))
}

#[test]
fn win64_images_carry_bc45_subsystem_version() {
    // Windows gives a subsystem >= 6.0 image the padded Vista frame and
    // modern dialog base units. BC4.5 programs lay out fixed-pixel windows
    // against tlink32's OS 1.0 / subsystem 3.10 metrics: at 6.0 RailC's
    // 300x192 Departures board lost 10px of client height and overflowed
    // its frame, and the About bitmaps no longer fit the dialog. Win64 images
    // must stamp the Borland versions, like the PE32 path does, whether they
    // come from compile_to_pe or from an mdlink-style object link.
    let src = "int main(void){ return 0; }";
    let direct = compile_to_pe(src.as_bytes()).expect("compile_to_pe");
    assert_eq!(
        version_fields(&direct),
        (1, 0, 3, 10),
        "compile_to_pe PE32+"
    );

    let resolver = mdbcc::pp::DefaultResolver {
        base_dir: PathBuf::from("."),
    };
    let obj = mdbcc::compile::compile_to_object_with(src.as_bytes(), "v.cpp", &resolver)
        .expect("compile_to_object");
    let linked = mdbcc::link::link(
        &[mdbcc::link::Input::Object(&obj)],
        &mdbcc::link::LinkOpts {
            subsystem: mdbcc::link::Subsystem::Console,
            ..mdbcc::link::LinkOpts::default()
        },
    )
    .expect("link");
    assert_eq!(version_fields(&linked), (1, 0, 3, 10), "mdlink PE32+");
}
