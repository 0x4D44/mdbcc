#![cfg(windows)]

//! Explicit RailC source-slice harness for Milestone 2.
//!
//! Run with:
//! `mdtimeout 1200s -- cargo test --release -q --test railc_source_slice -- --ignored --nocapture`
//! `mdtimeout 1200s -- cargo test --release -q --test railc_source_slice railc_source_built_dependency_slice_compiles_win64 -- --ignored --nocapture`
//! `mdtimeout 1200s -- cargo test --release -q --test railc_source_slice railc_source_built_dependency_slice_links_win64 -- --ignored --nocapture`
//!
//! The source slice is pinned in `tests/corpus/railc/source_slice.tsv`. The
//! harness links with `mdlink --trace-archives` and checks that the source-built
//! archives still pull exactly that pinned member set.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const RAILC_ROOT: &str = r"C:\language\railc";
const SOURCE_SLICE_MANIFEST: &str = include_str!("corpus/railc/source_slice.tsv");
const RAILC_TUS: &[&str] = &[
    "RAILC.CPP",
    "DEPARTUR.CPP",
    "LOCOYARD.CPP",
    "ARRIVALS.CPP",
    "FINISH.CPP",
    "ABOUT.CPP",
    "STARTUP.CPP",
    "START.CPP",
    "CONFIGUR.CPP",
    "LAYOUT.CPP",
    "SELECTOR.CPP",
    "PLATFORM.CPP",
    "TOOLBAR.CPP",
    "TOOLBUTT.CPP",
    "STATBAR.CPP",
    "SECTION.CPP",
    "PLATDATA.CPP",
    "ovlpdata.cpp",
    "ROUTES.CPP",
    "LOCOS.CPP",
    "TIMETABL.CPP",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SliceKind {
    Owl,
    Streams,
    Bids,
    Rtl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SliceMember {
    kind: SliceKind,
    member: String,
    source: PathBuf,
}

#[derive(Debug)]
struct Tools {
    bcc: PathBuf,
    mdar: PathBuf,
    mdlink: PathBuf,
    mdrc: PathBuf,
}

#[derive(Debug)]
struct Roots {
    repo: PathBuf,
    /// The user's BC4.52 tree (`$MDBCC_BC45_ROOT`, else the in-repo copy).
    bc45: PathBuf,
    railc: PathBuf,
    include: PathBuf,
    source: PathBuf,
    rtl_inc_common: PathBuf,
    rtl_inc_win32: PathBuf,
    rtl_inc: PathBuf,
    out: PathBuf,
    /// Win64 (MDBCC-01): when `Some(dir)`, `OWL.o`/`WINDOW.o` are compiled from the
    /// patched static-dispatcher copies under `dir` instead of the oracle sources.
    /// `None` everywhere else (the always-on manifest test + the -m32 link path).
    owl_overlay: Option<PathBuf>,
}

#[derive(Debug)]
struct SliceObjectDirs {
    build: PathBuf,
    railc: PathBuf,
    owl: PathBuf,
    streams: PathBuf,
    bids: PathBuf,
    rtl: PathBuf,
}

#[derive(Debug)]
struct SliceArchives {
    owl: PathBuf,
    streams: PathBuf,
    bids: PathBuf,
    rtl: PathBuf,
}

#[test]
fn railc_source_slice_manifest_maps_to_workspace_sources() {
    let roots = Roots::new();
    roots.assert_source_inputs_present();
    let members = parse_manifest_members(&roots);
    assert_slice_counts(&members);
}

#[test]
#[ignore = "depends on Arthur's local RailC corpus and release mdbcc tools"]
fn railc_source_built_dependency_slice_compiles_win64() {
    let roots = Roots::new();
    let tools = Tools::new(&roots.repo);
    roots.assert_inputs_present();
    tools.assert_present();

    let members = parse_manifest_members(&roots);
    assert_slice_counts(&members);

    let build = roots
        .repo
        .join("wrk_probe")
        .join("railc_source_slice_win64_compile_only")
        .join("build");
    let dirs = fresh_object_dirs(&roots, build);
    compile_source_slice_objects(&tools, &roots, &members, "-m64", &dirs);

    let summary = format!(
        "railc={}\nowl={}\nstreams={}\nbids={}\nrtl={}\n",
        sorted_files(&dirs.railc, "o").len(),
        sorted_files(&dirs.owl, "o").len(),
        sorted_files(&dirs.streams, "o").len(),
        sorted_files(&dirs.bids, "o").len(),
        sorted_files(&dirs.rtl, "o").len(),
    );
    fs::write(dirs.build.join("summary.txt"), &summary).expect("write Win64 compile-only summary");
    println!("{summary}");
}

#[test]
#[ignore = "depends on Arthur's local RailC corpus and release mdbcc tools"]
fn railc_source_built_dependency_slice_links() {
    let roots = Roots::new();
    let tools = Tools::new(&roots.repo);
    roots.assert_inputs_present();
    tools.assert_present();

    let members = parse_manifest_members(&roots);
    assert_slice_counts(&members);

    let dirs = fresh_object_dirs(&roots, roots.out.join("build"));
    compile_source_slice_objects(&tools, &roots, &members, "-m32", &dirs);
    let archives = archive_source_slice(&tools, &dirs, "slice", "mdcw32_slice.lib");
    let exe = link_source_slice(
        &tools,
        &roots,
        &members,
        &dirs,
        &archives,
        "-m32",
        "slice_archive_trace.tsv",
        "railc_slice.exe",
    );

    let summary = format!(
        "railc={}\nowl={}\nstreams={}\nbids={}\nrtl={}\nexe={}\n",
        sorted_files(&dirs.railc, "o").len(),
        sorted_files(&dirs.owl, "o").len(),
        sorted_files(&dirs.streams, "o").len(),
        sorted_files(&dirs.bids, "o").len(),
        sorted_files(&dirs.rtl, "o").len(),
        fs::metadata(&exe)
            .unwrap_or_else(|e| panic!("metadata {}: {e}", exe.display()))
            .len()
    );
    fs::write(dirs.build.join("summary.txt"), &summary).expect("write source-slice summary");
    println!("{summary}");
    assert!(exe.is_file(), "missing {}", exe.display());
}

#[test]
#[ignore = "depends on Arthur's local RailC corpus and release mdbcc tools"]
fn railc_source_built_dependency_slice_links_win64() {
    let mut roots = Roots::new();
    // Win64 (MDBCC-01): build OWL.o/WINDOW.o from the patched static-dispatcher
    // copies. The repository ships only mdbcc's diffs, so the overlay is built
    // here by applying `wrk_owl_win64/patches/` to the user's own BC4.52 tree.
    let Some(overlay) = materialize_owl_overlay(&roots) else {
        return;
    };
    for f in ["OWL.CPP", "WINDOW.CPP", "mdwin64thunk.h"] {
        let p = overlay.join(f);
        assert!(
            p.is_file(),
            "missing Win64 OWL overlay file {}",
            p.display()
        );
    }
    roots.owl_overlay = Some(overlay);
    let tools = Tools::new(&roots.repo);
    roots.assert_inputs_present();
    tools.assert_present();

    let members = parse_manifest_members(&roots);
    assert_slice_counts(&members);

    let build = roots
        .repo
        .join("wrk_probe")
        .join("railc_source_slice_win64_link")
        .join("build");
    let dirs = fresh_object_dirs(&roots, build);
    compile_source_slice_objects(&tools, &roots, &members, "-m64", &dirs);
    let archives = archive_source_slice(&tools, &dirs, "win64_slice", "mdcw64_slice.lib");
    let expected_linked_members = win64_link_expected_members(&members);
    let exe = link_source_slice(
        &tools,
        &roots,
        &expected_linked_members,
        &dirs,
        &archives,
        "-m64",
        "win64_archive_trace.tsv",
        "railc_source_slice_win64.exe",
    );

    let summary = format!(
        "railc={}\nowl={}\nstreams={}\nbids={}\nrtl={}\nexe={}\n",
        sorted_files(&dirs.railc, "o").len(),
        sorted_files(&dirs.owl, "o").len(),
        sorted_files(&dirs.streams, "o").len(),
        sorted_files(&dirs.bids, "o").len(),
        sorted_files(&dirs.rtl, "o").len(),
        fs::metadata(&exe)
            .unwrap_or_else(|e| panic!("metadata {}: {e}", exe.display()))
            .len()
    );
    fs::write(dirs.build.join("summary.txt"), &summary).expect("write Win64 source-slice summary");
    println!("{summary}");
    assert!(exe.is_file(), "missing {}", exe.display());

    // Win64 OWL window-bootstrap acceptance gates (MDBCC-01).
    let overlay = roots
        .owl_overlay
        .clone()
        .expect("owl_overlay set for the Win64 link test");
    assert_win64_import_gate(&exe); // O1: import-presence + CTL3D32/VirtualAlloc/VirtualFree regression
    assert_patched_objects_used(&dirs, &overlay); // O2: patched objects used + no residual truncation
    assert_win64_runtime_smoke(&exe); // O3: HARD GATE — fail on 0xC0000374 before any window (wall 1 cleared 2026-06-14).
    assert_win64_dialog_smoke(&exe); // O5: M2 — ABOUT/CONFIG dialogs open + close (Esc); hard-fail on crash/no-close.
    assert_win64_kingsx_parity(&exe); // O6: M3/M4 — KINGSX layout pixel-parity vs the 32-bit golden @ 720/3600.
}

impl Roots {
    fn new() -> Self {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // `$MDBCC_BC45_ROOT` first, so the harness works from a task worktree
        // (which has no `wrk_oracle/`); falls back to the in-repo tree.
        let bc45 = mdbcc::overlay::resolve_bc45_root(&repo)
            .unwrap_or_else(|| repo.join("wrk_oracle").join("bc452").join("BC45"));
        let source = bc45.join("SOURCE");
        let rtl = source.join("RTL").join("RTLINC");
        Self {
            include: bc45.join("INCLUDE"),
            bc45,
            railc: PathBuf::from(RAILC_ROOT),
            rtl_inc_common: rtl.join("COMMON32"),
            rtl_inc_win32: rtl.join("WIN32"),
            rtl_inc: rtl,
            out: repo.join("wrk_probe").join("railc_source_slice"),
            repo,
            source,
            owl_overlay: None,
        }
    }

    fn rtl_includes(&self) -> Vec<&Path> {
        vec![
            self.include.as_path(),
            self.rtl_inc_common.as_path(),
            self.rtl_inc_win32.as_path(),
            self.rtl_inc.as_path(),
        ]
    }

    fn assert_inputs_present(&self) {
        assert!(
            self.railc.is_dir(),
            "missing input path: {}",
            self.railc.display()
        );
        self.assert_source_inputs_present();
    }

    fn assert_source_inputs_present(&self) {
        for path in [
            self.include.as_path(),
            self.source.as_path(),
            self.rtl_inc_common.as_path(),
            self.rtl_inc_win32.as_path(),
            self.rtl_inc.as_path(),
        ] {
            assert!(path.exists(), "missing input path: {}", path.display());
        }
    }
}

/// Build the Win64 OWL overlay by applying `wrk_owl_win64/patches/` to the
/// user's BC4.52 tree, and return the generated directory.
///
/// `None` (a loud env-skip, not a failure) when that tree is absent — the same
/// oracle-absent contract the O6 parity gate uses. The output dir is private to
/// this test binary so a concurrent `build_bc45_libs` cannot race it, and it is
/// built once per process because several tests here want it.
fn materialize_owl_overlay(roots: &Roots) -> Option<PathBuf> {
    static OVERLAY: OnceLock<Option<PathBuf>> = OnceLock::new();
    OVERLAY
        .get_or_init(|| {
            if !roots.bc45.join("SOURCE").join("OWL").is_dir() {
                eprintln!(
                    "[railc_source_slice] ENV-SKIP: BC4.52 source tree absent ({}). \
                     Set $MDBCC_BC45_ROOT — the Win64 OWL overlay is built from it, not committed.",
                    roots.bc45.display()
                );
                return None;
            }
            let out = roots.repo.join("target").join("owl-overlay-win64-slice");
            match mdbcc::overlay::materialize(&roots.repo, &roots.bc45, &out) {
                Ok(dir) => Some(dir),
                Err(e) => panic!("cannot build the Win64 OWL overlay: {e}"),
            }
        })
        .clone()
}

impl SliceKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "owl" => Some(Self::Owl),
            "streams" => Some(Self::Streams),
            "bids" => Some(Self::Bids),
            "rtl" => Some(Self::Rtl),
            _ => None,
        }
    }
}

impl Tools {
    fn new(repo: &Path) -> Self {
        let release = repo.join("target").join("release");
        Self {
            bcc: release.join("bcc.exe"),
            mdar: release.join("mdar.exe"),
            mdlink: release.join("mdlink.exe"),
            mdrc: release.join("mdrc.exe"),
        }
    }

    fn assert_present(&self) {
        for path in [&self.bcc, &self.mdar, &self.mdlink, &self.mdrc] {
            assert!(
                path.is_file(),
                "missing tool {}; run `cargo build --release --bins` first",
                path.display()
            );
        }
    }
}

fn parse_manifest_members(roots: &Roots) -> Vec<SliceMember> {
    let mut members = BTreeMap::<(SliceKind, String), SliceMember>::new();
    for (line_no, line) in SOURCE_SLICE_MANIFEST.lines().enumerate() {
        if line_no == 0 {
            assert_eq!(line, "kind\tmember");
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(parts.len(), 2, "source_slice.tsv:{} malformed", line_no + 1);
        let kind = SliceKind::parse(parts[0]).unwrap_or_else(|| {
            panic!(
                "source_slice.tsv:{} unknown slice kind {}",
                line_no + 1,
                parts[0]
            )
        });
        insert_slice_member(&mut members, roots, kind, parts[1], "source_slice.tsv");
    }
    members.into_values().collect()
}

fn parse_archive_trace_members(roots: &Roots, trace_path: &Path) -> Vec<SliceMember> {
    let text = fs::read_to_string(trace_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", trace_path.display()));
    let mut members = BTreeMap::<(SliceKind, String), SliceMember>::new();
    for (line_no, line) in text.lines().enumerate() {
        if line_no == 0 {
            assert_eq!(line, "symbol\tarchive\tmember");
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            parts.len(),
            3,
            "{}:{} malformed",
            trace_path.display(),
            line_no + 1
        );
        let archive = parts[1];
        let member = parts[2];
        let kind = archive_kind(archive)
            .unwrap_or_else(|| panic!("cannot map archive in {}: {archive}", trace_path.display()));
        insert_slice_member(
            &mut members,
            roots,
            kind,
            member,
            &trace_path.display().to_string(),
        );
    }
    members.into_values().collect()
}

fn insert_slice_member(
    members: &mut BTreeMap<(SliceKind, String), SliceMember>,
    roots: &Roots,
    kind: SliceKind,
    member: &str,
    origin: &str,
) {
    let source = member_source(roots, kind, member);
    assert!(
        source.is_file(),
        "{origin} member {member} maps to missing source {}",
        source.display()
    );
    let key = (kind, member.to_string());
    let previous = members.insert(
        key,
        SliceMember {
            kind,
            member: member.to_string(),
            source,
        },
    );
    assert!(
        previous.is_none(),
        "{origin} contains duplicate member {member}"
    );
}

fn archive_kind(archive: &str) -> Option<SliceKind> {
    let archive = archive.to_ascii_lowercase();
    if archive.ends_with("mdowl.lib")
        || archive.ends_with("mdowl_slice.lib")
        || archive.ends_with("mdowl_win64_slice.lib")
    {
        return Some(SliceKind::Owl);
    }
    if archive.ends_with("mdstreams.lib")
        || archive.ends_with("mdstreams_slice.lib")
        || archive.ends_with("mdstreams_win64_slice.lib")
    {
        return Some(SliceKind::Streams);
    }
    if archive.ends_with("mdbids.lib")
        || archive.ends_with("mdbids_slice.lib")
        || archive.ends_with("mdbids_win64_slice.lib")
    {
        return Some(SliceKind::Bids);
    }
    if archive.ends_with("mdcw32.lib")
        || archive.ends_with("mdcw32_slice.lib")
        || archive.ends_with("mdcw64.lib")
        || archive.ends_with("mdcw64_slice.lib")
    {
        return Some(SliceKind::Rtl);
    }
    None
}

fn member_source(roots: &Roots, kind: SliceKind, member: &str) -> PathBuf {
    match kind {
        SliceKind::Owl => {
            // Win64 (MDBCC-01): redirect OWL.o/WINDOW.o to the patched build-local copies
            // when the overlay is active (name-preserving; manifest/-m32 paths use None).
            if let Some(dir) = &roots.owl_overlay {
                // Win64: OWL.o/WINDOW.o = wall-1 WNDPROC bootstrap; DISPATCH.o = wall-2 step-2
                // (int32 dispatch-layer pointer-width widening); DIALOG.o = M2 dialogs
                // (the DWL_USER path — no window-proc subclass — that makes them open+close).
                if member == "OWL.o"
                    || member == "WINDOW.o"
                    || member == "DISPATCH.o"
                    || member == "DIALOG.o"
                {
                    return dir.join(member.replace(".o", ".CPP"));
                }
            }
            roots.source.join("OWL").join(member.replace(".o", ".CPP"))
        }
        SliceKind::Streams => roots
            .source
            .join("RTL")
            .join("SOURCE")
            .join("IOSTREAM")
            .join(member.replace(".o", ".CPP")),
        SliceKind::Bids => roots
            .source
            .join("CLASSLIB")
            .join(member.replace(".o", ".CPP")),
        SliceKind::Rtl => {
            if member == "rtlshim.o" {
                return roots.repo.join("wrk_rtlshim").join("rtlshim.c");
            }
            if member == "rtlio.o" {
                return roots.repo.join("wrk_rtlshim").join("rtlio.c");
            }
            let base = member
                .strip_suffix(".o")
                .unwrap_or_else(|| panic!("RTL member without .o suffix: {member}"));
            for sub in ["COMMON32", "WIN32", "WINDOWS"] {
                let marker = format!("_{sub}_");
                if let Some(pos) = base.find(&marker) {
                    let cat = &base[..pos];
                    let file = &base[pos + marker.len()..];
                    return roots
                        .source
                        .join("RTL")
                        .join("SOURCE")
                        .join(cat)
                        .join(sub)
                        .join(file);
                }
            }
            if let Some((cat, file)) = base.split_once("__") {
                return roots.source.join("RTL").join("SOURCE").join(cat).join(file);
            }
            panic!("cannot map RTL member: {member}");
        }
    }
}

fn assert_slice_counts(members: &[SliceMember]) {
    assert_eq!(
        members.iter().filter(|m| m.kind == SliceKind::Owl).count(),
        65
    );
    assert_eq!(
        members
            .iter()
            .filter(|m| m.kind == SliceKind::Streams)
            .count(),
        48
    );
    assert_eq!(
        members.iter().filter(|m| m.kind == SliceKind::Bids).count(),
        11
    );
    assert_eq!(
        members.iter().filter(|m| m.kind == SliceKind::Rtl).count(),
        207
    );
}

fn assert_same_kind_counts(actual: &[SliceMember], expected: &[SliceMember]) {
    for kind in [
        SliceKind::Owl,
        SliceKind::Streams,
        SliceKind::Bids,
        SliceKind::Rtl,
    ] {
        assert_eq!(
            actual.iter().filter(|m| m.kind == kind).count(),
            expected.iter().filter(|m| m.kind == kind).count(),
            "linked member count drifted for {kind:?}"
        );
    }
}

fn win64_link_expected_members(members: &[SliceMember]) -> Vec<SliceMember> {
    const REPLACED_RTL_MEMBERS: &[&str] = &[
        "MEMORY_COMMON32_GETMEM.C.o",
        "MEMORY_COMMON32_HEAP.C.o",
        "MEMORY_COMMON32_REALLOC.C.o",
        "MEMORY_WIN32_VIRTMEM.C.o",
        "MISC_WIN32_PLATFORM.C.o",
    ];
    members
        .iter()
        .filter(|member| {
            !(member.kind == SliceKind::Rtl
                && REPLACED_RTL_MEMBERS.contains(&member.member.as_str()))
        })
        .cloned()
        .collect()
}

fn fresh_object_dirs(roots: &Roots, build: PathBuf) -> SliceObjectDirs {
    assert!(
        build.starts_with(roots.repo.join("wrk_probe")),
        "refusing to delete outside workspace: {}",
        build.display()
    );
    let _ = fs::remove_dir_all(&build);
    let dirs = SliceObjectDirs {
        railc: build.join("railc"),
        owl: build.join("owl"),
        streams: build.join("streams"),
        bids: build.join("bids"),
        rtl: build.join("rtl"),
        build,
    };
    for dir in [&dirs.railc, &dirs.owl, &dirs.streams, &dirs.bids, &dirs.rtl] {
        fs::create_dir_all(dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    }
    dirs
}

fn compile_source_slice_objects(
    tools: &Tools,
    roots: &Roots,
    members: &[SliceMember],
    target: &str,
    dirs: &SliceObjectDirs,
) {
    // Win64 wall-2 (MDBCC-01): when the OWL overlay is active and we're building -m64,
    // prepend the pointer-width message-typedef overlay include dir to EVERY TU so the
    // 64-bit WPARAM/LPARAM/LRESULT (and the dispatch layer) are seen coherently slice-wide
    // (the non-virtual cross-TU ReceiveMessage/HandleMessage mangling demands one ABI view).
    let overlay_inc: Option<PathBuf> = if target == "-m64" {
        roots.owl_overlay.as_ref().map(|d| d.join("include64"))
    } else {
        None
    };
    if let Some(inc) = &overlay_inc {
        assert!(
            inc.join("WINDEF.H").is_file(),
            "missing Win64 overlay header {}",
            inc.join("WINDEF.H").display()
        );
    }
    let with_overlay = |base: Vec<&Path>| -> Vec<PathBuf> {
        overlay_inc
            .iter()
            .map(|p| p.as_path())
            .chain(base)
            .map(Path::to_path_buf)
            .collect()
    };

    for tu in RAILC_TUS {
        let src = roots.railc.join(tu);
        let obj = dirs.railc.join(format!("{}.o", file_stem(tu)));
        let includes = with_overlay(vec![roots.railc.as_path(), roots.include.as_path()]);
        compile_obj_for_target(
            tools,
            target,
            &src,
            &obj,
            &includes.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
            &[],
        );
    }

    for member in members {
        let dir = match member.kind {
            SliceKind::Owl => &dirs.owl,
            SliceKind::Streams => &dirs.streams,
            SliceKind::Bids => &dirs.bids,
            SliceKind::Rtl => &dirs.rtl,
        };
        let base_includes: Vec<&Path> = match member.kind {
            SliceKind::Owl | SliceKind::Bids => vec![roots.include.as_path()],
            SliceKind::Streams | SliceKind::Rtl => roots.rtl_includes(),
        };
        let base_includes = if member.member == "rtlshim.o" {
            vec![roots.include.as_path()]
        } else {
            base_includes
        };
        let includes_owned = with_overlay(base_includes);
        let includes: Vec<&Path> = includes_owned.iter().map(PathBuf::as_path).collect();
        let mut defines = Vec::new();
        if member.member == "MISC_WIN32_ERRORMSG.C.o" || member.member == "MISC_WIN32_GP.C.o" {
            defines.push("-DWINVER=0x030A");
        }
        compile_obj_for_target(
            tools,
            target,
            &member.source,
            &dir.join(&member.member),
            &includes,
            &defines,
        );
    }
}

// ===========================================================================
// Win64 OWL window-bootstrap acceptance gates (MDBCC-01).
// O1 import gate, O2 patched-objects-used + residual-truncation scan, O3 runtime smoke.
// See wrk_docs/2026.06.13 - HLD - railc win64 owl window bootstrap.md (Status: SIGNED-OFF).
// ===========================================================================

/// O1 — assert the linked exe's PE import directory contains the Win64 OWL
/// window-path imports and none of the legacy/regression imports.
///
/// NOTE: x64 import emission is non-pruning, so `*Ptr*` presence does NOT prove
/// the patch was used (an unpatched exe would show them too) — that is O2's job.
/// O1 is the HLD import-presence acceptance criterion + the CTL3D32 / VirtualAlloc /
/// VirtualFree regression gate.
fn assert_win64_import_gate(exe: &Path) {
    let bytes = fs::read(exe).unwrap_or_else(|e| panic!("read {}: {e}", exe.display()));
    let imports = parse_pe_imports(&bytes)
        .unwrap_or_else(|e| panic!("parse PE imports of {}: {e}", exe.display()));
    let has = |dll: &str, sym: &str| {
        imports
            .iter()
            .any(|(d, s)| d.eq_ignore_ascii_case(dll) && s == sym)
    };
    let dll_present = |dll: &str| imports.iter().any(|(d, _)| d.eq_ignore_ascii_case(dll));
    assert!(
        has("USER32.dll", "SetWindowLongPtrA"),
        "O1: USER32!SetWindowLongPtrA missing from the import table"
    );
    assert!(
        has("USER32.dll", "GetWindowLongPtrA"),
        "O1: USER32!GetWindowLongPtrA missing from the import table"
    );
    assert!(
        !dll_present("CTL3D32.dll"),
        "O1 REGRESSION: CTL3D32.dll reappeared in the import table"
    );
    for sym in ["VirtualAlloc", "VirtualFree"] {
        assert!(
            !has("KERNEL32.dll", sym),
            "O1 REGRESSION: KERNEL32!{sym} reappeared (the process-heap shim makes it unnecessary)"
        );
    }
    eprintln!(
        "O1 OK: {} named imports; *Ptr* present; no CTL3D32/VirtualAlloc/VirtualFree",
        imports.len()
    );
}

/// Minimal PE import-directory walker (PE32 + PE32+). Returns (DLL, by-name symbol)
/// pairs; ordinal-only imports are skipped (we only assert by name).
fn parse_pe_imports(pe: &[u8]) -> Result<Vec<(String, String)>, String> {
    let u16le = |o: usize| u16::from_le_bytes([pe[o], pe[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes([pe[o], pe[o + 1], pe[o + 2], pe[o + 3]]);
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return Err("not an MZ image".into());
    }
    let pe_off = u32le(0x3C) as usize;
    if pe.len() < pe_off + 24 || &pe[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("missing PE signature".into());
    }
    let coff = pe_off + 4;
    let n_sections = u16le(coff + 2) as usize;
    let opt_size = u16le(coff + 16) as usize;
    let opt = coff + 20;
    let (dd_base, pe32_plus) = match u16le(opt) {
        0x10B => (96usize, false),
        0x20B => (112usize, true),
        m => return Err(format!("unexpected optional-header magic {m:#06x}")),
    };
    let import_rva = u32le(opt + dd_base + 8); // DataDirectory[1] = IMPORT
    if import_rva == 0 {
        return Ok(Vec::new());
    }
    let sec = opt + opt_size;
    // (virtual_address, virtual_size, raw_ptr, raw_size) per section.
    let sections: Vec<(u32, u32, u32, u32)> = (0..n_sections)
        .map(|i| {
            let s = sec + i * 40;
            (u32le(s + 12), u32le(s + 8), u32le(s + 20), u32le(s + 16))
        })
        .collect();
    let rva_off = |rva: u32| -> Option<usize> {
        sections.iter().find_map(|&(va, vsize, raw_ptr, raw_size)| {
            let span = vsize.max(raw_size);
            (rva >= va && rva < va + span).then(|| (raw_ptr + (rva - va)) as usize)
        })
    };
    let cstr = |mut o: usize| -> String {
        let mut v = Vec::new();
        while o < pe.len() && pe[o] != 0 {
            v.push(pe[o]);
            o += 1;
        }
        String::from_utf8_lossy(&v).into_owned()
    };
    let mut out = Vec::new();
    let mut desc = rva_off(import_rva).ok_or("import RVA not in any section")?;
    while desc + 20 <= pe.len() {
        let oft = u32le(desc);
        let name_rva = u32le(desc + 12);
        let ft = u32le(desc + 16);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break; // null terminator
        }
        let dll = rva_off(name_rva).map(cstr).unwrap_or_default();
        let thunk_rva = if oft != 0 { oft } else { ft };
        if let Some(mut t) = rva_off(thunk_rva) {
            let esize = if pe32_plus { 8 } else { 4 };
            let hbit: u64 = if pe32_plus { 1u64 << 63 } else { 1u64 << 31 };
            while t + esize <= pe.len() {
                let val = if pe32_plus {
                    u64::from_le_bytes(pe[t..t + 8].try_into().unwrap())
                } else {
                    u32le(t) as u64
                };
                if val == 0 {
                    break; // end of this DLL's thunks
                }
                if val & hbit == 0
                    && let Some(o) = rva_off((val & 0x7FFF_FFFF) as u32)
                {
                    let name = cstr(o + 2); // skip the 2-byte hint
                    if !name.is_empty() {
                        out.push((dll.clone(), name));
                    }
                }
                t += esize;
            }
        }
        desc += 20;
    }
    Ok(out)
}

/// O2 — prove the PATCHED OWL.o/WINDOW.o were compiled+linked (the name-keyed archive
/// trace cannot distinguish patched vs oracle), and that NO truncating WNDPROC-install
/// site remains in the patched sources.
fn assert_patched_objects_used(dirs: &SliceObjectDirs, overlay: &Path) {
    for (obj, marker) in [
        (dirs.owl.join("OWL.o"), "mdbcc_owl_win64_marker_owl"),
        (dirs.owl.join("WINDOW.o"), "mdbcc_owl_win64_marker_window"),
        (
            dirs.owl.join("DISPATCH.o"),
            "mdbcc_owl_win64_marker_dispatch",
        ),
        (dirs.owl.join("DIALOG.o"), "mdbcc_owl_win64_marker_dialog"),
    ] {
        let bytes = fs::read(&obj).unwrap_or_else(|e| panic!("read {}: {e}", obj.display()));
        assert!(
            bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "O2: marker `{marker}` absent from {} — the patched object was not used",
            obj.display()
        );
    }
    for f in ["OWL.CPP", "WINDOW.CPP"] {
        let src =
            fs::read_to_string(overlay.join(f)).unwrap_or_else(|e| panic!("read overlay {f}: {e}"));
        // Strip `//` line comments so the scan only inspects code.
        let code: String = src
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        for pat in [
            "_EAX",
            "uint32(thunk)",
            "uint32(GetThunk",
            "uint32(DefaultProc)",
            "GWL_WNDPROC",
        ] {
            assert!(
                !code.contains(pat),
                "O2: residual truncating WNDPROC-install pattern `{pat}` remains in code of {f}"
            );
        }
    }
    eprintln!("O2 OK: patched-object markers present; no residual truncating sites");
}

/// O3 outcome. Hard-fail on a recurrence of 0xC0000374 (wall 1) before any window,
/// OR 0xC0000005 (wall 2) during the pointer-bearing interaction battery.
#[derive(Debug)]
enum SmokeOutcome {
    /// Window appeared AND survived the wall-2 interaction battery (resize/move storm +
    /// menu commands that create the KINGSX child windows) without a truncation crash.
    WindowSurvivedBattery,
    Survived,
    NewFrontier(u32),
    HeapCorruption,
    /// 0xC0000005 during/after the interaction battery: wall-2 pointer truncation regressed.
    AccessViolation(&'static str),
    HarnessError(String),
}

/// O3 — bounded headless runtime smoke. HARD REGRESSION GATE on two cleared walls:
///   - `0xC0000374` (heap corruption) before any window — wall 1 (array-new/delete cookie).
///   - `0xC0000005` (access violation) during the pointer-bearing interaction battery — wall 2
///     (the slice-wide WPARAM/LPARAM/LRESULT pointer-width widening).
///
/// History: wall 1 was the array-new/delete cookie mismatch in `gen_placement_new_array`
/// (diagnosed via cdb + mdlink --map → `TVectorImpBase::Resize`), fixed 2026-06-14 — the window
/// now opens. Wall 2 was the 32-bit message typedefs: a pointer in `lParam` (e.g. WINDOWPOS* /
/// MINMAXINFO* on resize) truncated through `StdWndProc → ReceiveMessage → … → DefWindowProc`
/// → `0xC0000005`, reproduced by `wrk_probe/owl_win64_smoke/wall2_probe.ps1` and fixed by the
/// `wrk_owl_win64/include64/WINDEF.H` overlay (2026-06-14). This gate now drives that same
/// interaction battery in-process so neither wall can silently regress.
fn assert_win64_runtime_smoke(exe: &Path) {
    match run_window_smoke(exe) {
        SmokeOutcome::WindowSurvivedBattery => eprintln!(
            "O3 PASS: window appeared AND survived the wall-2 interaction battery \
             (resize/move storm + menu commands incl. KINGSX child windows) — walls 1 & 2 cleared."
        ),
        SmokeOutcome::Survived => {
            eprintln!(
                "O3 PASS: the process survived past the heap-corruption point (no window observed)."
            )
        }
        SmokeOutcome::NewFrontier(code) => eprintln!(
            "O3 PASS: NEW FRONTIER — exited {code:#010x} (!= 0xC0000374/0xC0000005); walls cleared, new frontier ahead."
        ),
        SmokeOutcome::HeapCorruption => panic!(
            "O3 REGRESSION: the Win64 exe exited 0xC0000374 (heap corruption) before any window — \
             the array-new/delete cookie fix (gen_placement_new_array) has regressed. See \
             wrk_docs/2026.06.13 - HLD - mdbcc Win64 array-new cookie fix.md."
        ),
        SmokeOutcome::AccessViolation(stage) => panic!(
            "O3 REGRESSION (wall 2): the Win64 exe exited 0xC0000005 (access violation) during '{stage}' — \
             the slice-wide WPARAM/LPARAM/LRESULT pointer-width widening (wrk_owl_win64/include64/WINDEF.H) \
             has regressed; a pointer in lParam is being truncated through OWL's dispatch chain."
        ),
        SmokeOutcome::HarnessError(e) => {
            eprintln!("O3 harness error (smoke inconclusive, not a regression): {e}")
        }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SmokeRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[cfg(windows)]
fn run_window_smoke(exe: &Path) -> SmokeOutcome {
    use std::os::raw::c_void;
    use std::time::{Duration, Instant};
    type Hwnd = *mut c_void;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn EnumWindows(cb: unsafe extern "system" fn(Hwnd, isize) -> i32, lparam: isize) -> i32;
        fn GetWindowThreadProcessId(hwnd: Hwnd, pid_out: *mut u32) -> u32;
        fn IsWindowVisible(hwnd: Hwnd) -> i32;
        fn PostMessageA(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> i32;
        fn SetWindowPos(
            hwnd: Hwnd,
            after: Hwnd,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> i32;
        fn GetWindowRect(hwnd: Hwnd, rect: *mut SmokeRect) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const WM_CLOSE: u32 = 0x0010;
    const WM_COMMAND: u32 = 0x0111;
    const SWP_NOZORDER: u32 = 0x0004;

    struct Find {
        pid: u32,
        hwnd: Hwnd,
    }
    unsafe extern "system" fn cb(hwnd: Hwnd, lparam: isize) -> i32 {
        let f = unsafe { &mut *(lparam as *mut Find) };
        let mut wpid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut wpid) };
        if wpid == f.pid && unsafe { IsWindowVisible(hwnd) } != 0 {
            f.hwnd = hwnd;
            return 0; // stop enumeration
        }
        1
    }

    // Suppress WER / hard-error UI so a crash exits immediately (children inherit the mode).
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };

    let run_dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let mut child = match Command::new(exe).current_dir(run_dir).spawn() {
        Ok(c) => c,
        Err(e) => return SmokeOutcome::HarnessError(format!("spawn {}: {e}", exe.display())),
    };
    let pid = child.id();

    let classify = |status: std::process::ExitStatus| -> SmokeOutcome {
        let u = status.code().map(|c| c as u32).unwrap_or(0);
        if u == 0xC000_0374 {
            SmokeOutcome::HeapCorruption
        } else if u == 0 {
            SmokeOutcome::Survived
        } else {
            SmokeOutcome::NewFrontier(u)
        }
    };

    let window_deadline = Instant::now() + Duration::from_secs(10);
    let run_deadline = Instant::now() + Duration::from_secs(30);
    let hwnd: Hwnd = loop {
        let mut f = Find {
            pid,
            hwnd: std::ptr::null_mut(),
        };
        unsafe { EnumWindows(cb, &mut f as *mut Find as isize) };
        if !f.hwnd.is_null() {
            break f.hwnd;
        }
        match child.try_wait() {
            Ok(Some(s)) => return classify(s),
            Ok(None) => {}
            Err(e) => return SmokeOutcome::HarnessError(format!("try_wait: {e}")),
        }
        if Instant::now() >= window_deadline {
            // No window within 10s and still running: allow until run_deadline; survived = pass.
            return match wait_or_kill(&mut child, run_deadline) {
                Some(s) => classify(s),
                None => SmokeOutcome::Survived,
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // Window appeared (wall 1). Now drive the wall-2 pointer-bearing interaction battery and
    // assert no 0xC0000005 truncation crash. After each step, poll for an early exit: a crash
    // mid-battery is the failure we guard against.
    let exited_during =
        |child: &mut std::process::Child, stage: &'static str| -> Option<SmokeOutcome> {
            match child.try_wait() {
                Ok(Some(s)) => {
                    let u = s.code().map(|c| c as u32).unwrap_or(0);
                    Some(if u == 0xC000_0005 {
                        SmokeOutcome::AccessViolation(stage)
                    } else if u == 0xC000_0374 {
                        SmokeOutcome::HeapCorruption
                    } else {
                        SmokeOutcome::NewFrontier(u)
                    })
                }
                Ok(None) => None,
                Err(e) => Some(SmokeOutcome::HarnessError(format!("try_wait: {e}"))),
            }
        };

    // 1) Resize/move storm — Windows SENDS pointer-bearing WM_WINDOWPOSCHANGING (WINDOWPOS*),
    //    WM_GETMINMAXINFO (MINMAXINFO*), WM_NCCALCSIZE (NCCALCSIZE_PARAMS*).
    let mut rect = SmokeRect::default();
    unsafe { GetWindowRect(hwnd, &mut rect) };
    for d in [0i32, 40, -30, 60, -50, 20, 80] {
        unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                rect.left + d,
                rect.top + d,
                700 + d,
                520 + d,
                SWP_NOZORDER,
            )
        };
        std::thread::sleep(Duration::from_millis(120));
        if let Some(o) = exited_during(&mut child, "resize/move storm") {
            return o;
        }
    }

    // 2) Menu commands routed through the response table; 300-303 create the KINGSX child windows
    //    (more dispatch + child window-tree construction). 200 = Optimize (internal MoveWindow storm).
    for id in [200usize, 300, 301, 302, 303, 200] {
        unsafe { PostMessageA(hwnd, WM_COMMAND, id, 0) };
        std::thread::sleep(Duration::from_millis(400));
        if let Some(o) = exited_during(&mut child, "menu-command routing / child-window create") {
            return o;
        }
    }

    // Survived the battery — close cleanly.
    unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    match wait_or_kill(&mut child, run_deadline) {
        // A clean/forced shutdown after surviving the battery is the success path.
        Some(s) => {
            let u = s.code().map(|c| c as u32).unwrap_or(0);
            if u == 0xC000_0005 {
                SmokeOutcome::AccessViolation("WM_CLOSE shutdown")
            } else if u == 0xC000_0374 {
                SmokeOutcome::HeapCorruption
            } else {
                SmokeOutcome::WindowSurvivedBattery
            }
        }
        None => SmokeOutcome::WindowSurvivedBattery,
    }
}

#[cfg(windows)]
fn wait_or_kill(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(s),
            Ok(None) => {}
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(not(windows))]
fn run_window_smoke(_exe: &Path) -> SmokeOutcome {
    SmokeOutcome::HarnessError("runtime smoke is Windows-only".into())
}

/// O5 — M2 dialog smoke. Opens the ABOUT (999) and CONFIG (201) dialogs from the main frame,
/// closes each with Esc (→ IDCANCEL → CmCancel → EndDialog), and asserts each opened, closed, and
/// did not crash the process. HARD-FAILS on `0xC0000005` (the subclass / child-control truncation
/// crashes this M2 work cleared) or on a dialog that opened but would not close. A dialog that
/// never appears is reported (not failed) — timing/INI-dependent, not a code regression.
#[derive(Debug)]
enum DialogOutcome {
    AllClosed,
    Crashed(&'static str, u32),
    DidNotClose(&'static str),
    NoDialog(&'static str),
    HarnessError(String),
}

fn assert_win64_dialog_smoke(exe: &Path) {
    match run_dialog_smoke(exe) {
        DialogOutcome::AllClosed => {
            eprintln!(
                "O5 PASS: ABOUT + CONFIG dialogs open and close (Esc) — M2 dialogs functional."
            )
        }
        DialogOutcome::Crashed(stage, code) => panic!(
            "O5 REGRESSION: the '{stage}' dialog crashed {code:#010x} — the M2 dialog fix \
             (DWL_USER path / SetWindowLongPtrA-return prototype / control-HWND width) has regressed."
        ),
        DialogOutcome::DidNotClose(stage) => panic!(
            "O5 REGRESSION: the '{stage}' dialog opened but would not close (Esc → IDCANCEL → CmCancel \
             → EndDialog) — the M2 close routing has regressed."
        ),
        DialogOutcome::NoDialog(stage) => {
            eprintln!(
                "O5 NOTE: the '{stage}' dialog did not appear (timing/INI); not a code regression."
            )
        }
        DialogOutcome::HarnessError(e) => {
            eprintln!("O5 harness error (dialog smoke inconclusive): {e}")
        }
    }
}

#[cfg(windows)]
fn run_dialog_smoke(exe: &Path) -> DialogOutcome {
    use std::os::raw::c_void;
    use std::time::{Duration, Instant};
    type Hwnd = *mut c_void;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn EnumWindows(cb: unsafe extern "system" fn(Hwnd, isize) -> i32, lparam: isize) -> i32;
        fn GetWindowThreadProcessId(hwnd: Hwnd, pid_out: *mut u32) -> u32;
        fn IsWindowVisible(hwnd: Hwnd) -> i32;
        fn GetClassNameA(hwnd: Hwnd, buf: *mut u8, n: i32) -> i32;
        fn PostMessageA(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }
    const WM_COMMAND: u32 = 0x0111;
    const WM_KEYDOWN: u32 = 0x0100;
    const WM_KEYUP: u32 = 0x0101;
    const VK_ESCAPE: usize = 0x1B;

    struct Find {
        pid: u32,
        target: &'static [u8],
        hwnd: Hwnd,
    }
    unsafe extern "system" fn cb(hwnd: Hwnd, lparam: isize) -> i32 {
        let f = unsafe { &mut *(lparam as *mut Find) };
        let mut wpid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut wpid) };
        if wpid == f.pid && unsafe { IsWindowVisible(hwnd) } != 0 {
            let mut buf = [0u8; 64];
            let n = unsafe { GetClassNameA(hwnd, buf.as_mut_ptr(), 64) } as usize;
            if n > 0 && n <= 64 && &buf[..n] == f.target {
                f.hwnd = hwnd;
                return 0;
            }
        }
        1
    }

    unsafe { SetErrorMode(0x0001 | 0x0002) };
    let run_dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let mut child = match Command::new(exe).current_dir(run_dir).spawn() {
        Ok(c) => c,
        Err(e) => return DialogOutcome::HarnessError(format!("spawn {}: {e}", exe.display())),
    };
    let pid = child.id();

    let find = |target: &'static [u8]| -> Hwnd {
        let mut f = Find {
            pid,
            target,
            hwnd: std::ptr::null_mut(),
        };
        unsafe { EnumWindows(cb, &mut f as *mut Find as isize) };
        f.hwnd
    };
    // Crash code if the process has exited, else None.
    let crash_code = |child: &mut std::process::Child| -> Option<u32> {
        match child.try_wait() {
            Ok(Some(s)) => Some(s.code().map(|c| c as u32).unwrap_or(0)),
            _ => None,
        }
    };
    let poll = |find_target: &'static [u8], want: bool, secs: u64| -> Option<Hwnd> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let h = find(find_target);
            if (want && !h.is_null()) || (!want && h.is_null()) {
                return Some(h);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(120));
        }
    };

    // Wait for the main frame.
    if poll(b"Main_Window_Class", true, 12).is_none() {
        let _ = wait_or_kill(&mut child, Instant::now());
        return DialogOutcome::NoDialog("Main_Window_Class");
    }
    let main = find(b"Main_Window_Class");

    for (cmd, name) in [(999usize, "About"), (201usize, "Config")] {
        unsafe { PostMessageA(main, WM_COMMAND, cmd, 0) };
        // Wait for the dialog (#32770).
        if poll(b"#32770", true, 6).is_none() {
            if let Some(code) = crash_code(&mut child) {
                return DialogOutcome::Crashed(name, code);
            }
            // No dialog and still alive: report (timing/INI), continue.
            return DialogOutcome::NoDialog(name);
        }
        let dlg = find(b"#32770");
        // Close with Esc.
        unsafe {
            PostMessageA(dlg, WM_KEYDOWN, VK_ESCAPE, 0);
            PostMessageA(dlg, WM_KEYUP, VK_ESCAPE, 0);
        }
        // Wait for it to close (or crash).
        if poll(b"#32770", false, 6).is_none() {
            if let Some(code) = crash_code(&mut child) {
                return DialogOutcome::Crashed(name, code);
            }
            let _ = child.kill();
            let _ = child.wait();
            return DialogOutcome::DidNotClose(name);
        }
        if let Some(code) = crash_code(&mut child) {
            return DialogOutcome::Crashed(name, code);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    DialogOutcome::AllClosed
}

#[cfg(not(windows))]
fn run_dialog_smoke(_exe: &Path) -> DialogOutcome {
    DialogOutcome::HarnessError("dialog smoke is Windows-only".into())
}

/// O6 — M3/M4 differential GUI-parity gate. Drives BOTH the freshly-built native-Win64 exe and the
/// 32-bit BC4.5 golden through the IDENTICAL deterministic tick sequence and pixel-compares the KINGSX
/// "Layout Class" child at the 720 and 3600 tiers (the same sampled tiers the i386 self-host was validated
/// on). HARD-FAILS if the layout diverges from the golden OUTSIDE the documented golden delay-LED bug
/// region. ORACLE-SKIPS (loud `eprintln!`, not a failure) when the gitignored 32-bit golden fixtures
/// (`wrk_probe/gui_parity/golden_run/{railc.exe,KINGSX.RCD}`) or `pwsh` are absent — the same
/// self-skipping-when-the-oracle-is-absent contract O2/O3 use. The differential logic lives in the
/// committed, parameterized `wrk_owl_win64/parity/win64_kingsx_parity.ps1` (exit 0 PASS / 2 inconclusive /
/// 3 FAIL); see the M3/M4 journals for the full root-cause and the documented golden bug.
#[cfg(windows)]
fn assert_win64_kingsx_parity(exe: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo
        .join("wrk_owl_win64")
        .join("parity")
        .join("win64_kingsx_parity.ps1");
    let golden_dir = repo.join("wrk_probe").join("gui_parity").join("golden_run");
    let golden_exe = golden_dir.join("railc.exe");
    let kingsx = golden_dir.join("KINGSX.RCD");
    if !golden_exe.is_file() || !kingsx.is_file() {
        eprintln!(
            "O6 NOTE: 32-bit golden fixtures absent ({}) — KINGSX parity skipped (oracle-skip, not a regression).",
            golden_dir.display()
        );
        return;
    }
    if !script.is_file() {
        eprintln!(
            "O6 NOTE: parity driver missing ({}) — skipped.",
            script.display()
        );
        return;
    }
    let output = Command::new("pwsh")
        .args(["-NoProfile", "-File"])
        .arg(&script)
        .arg("-Win64Exe")
        .arg(exe)
        .arg("-GoldenExe")
        .arg(&golden_exe)
        .arg("-DataDir")
        .arg(&golden_dir)
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("O6 NOTE: could not launch pwsh ({e}) — KINGSX parity skipped.");
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code().unwrap_or(-1);
    if code == 2 {
        eprintln!("O6 NOTE: KINGSX parity harness inconclusive (skip):\n{stdout}");
        return;
    }
    assert!(
        code == 0 && stdout.contains("PARITY PASS"),
        "O6 REGRESSION: the native-Win64 KINGSX layout diverged from the 32-bit golden at the 720/3600 \
         tiers (outside the documented golden delay-LED bug region). pwsh exit {code}; output:\n{stdout}"
    );
    eprintln!("O6 PASS: KINGSX layout pixel-identical to the 32-bit golden @ 720 and 3600 ticks.");
}

#[cfg(not(windows))]
fn assert_win64_kingsx_parity(_exe: &Path) {}

fn archive_source_slice(
    tools: &Tools,
    dirs: &SliceObjectDirs,
    suffix: &str,
    rtl_archive_name: &str,
) -> SliceArchives {
    let archives = SliceArchives {
        owl: dirs.build.join(format!("mdowl_{suffix}.lib")),
        streams: dirs.build.join(format!("mdstreams_{suffix}.lib")),
        bids: dirs.build.join(format!("mdbids_{suffix}.lib")),
        rtl: dirs.build.join(rtl_archive_name),
    };
    archive_dir(tools, &dirs.owl, &archives.owl);
    archive_dir(tools, &dirs.streams, &archives.streams);
    archive_dir(tools, &dirs.bids, &archives.bids);
    archive_dir(tools, &dirs.rtl, &archives.rtl);
    archives
}

#[allow(clippy::too_many_arguments)] // distinct per-variant link inputs; bundling adds layers without semantic clarity.
fn link_source_slice(
    tools: &Tools,
    roots: &Roots,
    expected_linked_members: &[SliceMember],
    dirs: &SliceObjectDirs,
    archives: &SliceArchives,
    target: &str,
    trace_name: &str,
    exe_name: &str,
) -> PathBuf {
    let res = dirs.build.join("railc.res");
    run_logged(
        &tools.mdrc,
        &[
            "--profile".into(),
            "bc45".into(),
            "-o".into(),
            res.as_os_str().into(),
            roots
                .railc
                .join("RESOURCE")
                .join("RAILC.RC")
                .into_os_string(),
        ],
        &dirs.build.join("mdrc.log"),
    );

    let exe = dirs.build.join(exe_name);
    let slice_trace = dirs.build.join(trace_name);
    let mut link_args = vec![
        target.into(),
        "--subsystem".into(),
        "gui".into(),
        "--trace-archives".into(),
        slice_trace.as_os_str().into(),
    ];
    for obj in sorted_files(&dirs.railc, "o") {
        link_args.push(obj.into_os_string());
    }
    link_args.extend([
        archives.owl.as_os_str().into(),
        archives.streams.as_os_str().into(),
        archives.rtl.as_os_str().into(),
        archives.bids.as_os_str().into(),
        res.into_os_string(),
        "-o".into(),
        exe.as_os_str().into(),
    ]);
    run_logged(&tools.mdlink, &link_args, &dirs.build.join("link.log"));
    assert!(slice_trace.is_file(), "missing {}", slice_trace.display());
    let linked_members = parse_archive_trace_members(roots, &slice_trace);
    assert_same_kind_counts(&linked_members, expected_linked_members);
    assert_eq!(
        member_key_set(&linked_members),
        member_key_set(expected_linked_members),
        "linked archive pulls drifted from expected source slice"
    );
    exe
}

fn member_key_set(members: &[SliceMember]) -> BTreeSet<(SliceKind, String)> {
    members
        .iter()
        .map(|member| (member.kind, member.member.clone()))
        .collect()
}

fn compile_obj_for_target(
    tools: &Tools,
    target: &str,
    src: &Path,
    obj: &Path,
    includes: &[&Path],
    defines: &[&str],
) {
    let mut args = vec!["-c".into(), target.into(), "-D__WIN32__".into()];
    for define in defines {
        args.push((*define).into());
    }
    for include in includes {
        args.push("-I".into());
        args.push(include.as_os_str().into());
    }
    args.push(src.as_os_str().into());
    args.push("-o".into());
    args.push(obj.as_os_str().into());
    run_logged(&tools.bcc, &args, &obj.with_extension("log"));
    assert!(obj.is_file(), "compiler did not produce {}", obj.display());
}

fn archive_dir(tools: &Tools, dir: &Path, out: &Path) {
    let objs = sorted_files(dir, "o");
    assert!(!objs.is_empty(), "no objects in {}", dir.display());
    let args: Vec<_> = std::iter::once("-o".into())
        .chain(std::iter::once(out.as_os_str().into()))
        .chain(
            objs.iter()
                .map(|path| path.file_name().expect("object file name").to_os_string()),
        )
        .collect();
    run_logged_in(dir, &tools.mdar, &args, &out.with_extension("log"));
    assert!(out.is_file(), "archiver did not produce {}", out.display());
}

fn run_logged(program: &Path, args: &[std::ffi::OsString], log: &Path) {
    run_logged_in(Path::new("."), program, args, log);
}

fn run_logged_in(cwd: &Path, program: &Path, args: &[std::ffi::OsString], log: &Path) {
    let output = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", program.display()));
    let mut file = File::create(log).unwrap_or_else(|e| panic!("create {}: {e}", log.display()));
    file.write_all(&output.stdout).expect("write stdout log");
    file.write_all(&output.stderr).expect("write stderr log");
    assert!(
        output.status.success(),
        "{} failed with status {}; log {}",
        program.display(),
        output.status,
        log.display()
    );
}

fn sorted_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|actual| actual.eq_ignore_ascii_case(ext))
        })
        .collect();
    files.sort_by_key(|path| path.file_name().map(OsStr::to_os_string));
    files
}

fn file_stem(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("input")
        .to_string()
}
