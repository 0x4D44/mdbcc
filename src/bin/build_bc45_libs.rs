//! `build_bc45_libs` — produce the mdbcc-built BC4.52 dependency libraries.
//!
//! The mdbcc toolchain reimplements Borland C++ 4.52. Just as the original
//! toolchain shipped its runtime/framework libraries (`OWLWF.LIB`, `CW32.LIB`,
//! …), mdbcc owns its equivalents. This binary uses the freshly-built release
//! `bcc`/`mdar` to compile the OWL framework, the iostreams slice, the C/C++
//! RTL, and the BIDS container library from BC4.52 *source* into four
//! MS-format archives:
//!
//! | Archive          | Contents                                            |
//! |------------------|-----------------------------------------------------|
//! | `mdowl.lib`      | OWL framework (`SOURCE/OWL/*.CPP`)                   |
//! | `mdstreams.lib`  | curated iostreams slice (`SOURCE/RTL/SOURCE/IOSTREAM`)|
//! | `mdcw32.lib`     | C/C++ RTL (`SOURCE/RTL/SOURCE/**`) + heap/io shim    |
//! | `mdbids.lib`     | BIDS container library (`SOURCE/CLASSLIB/*.CPP`)     |
//!
//! Output lands in `target/bc45-libs/` for the default Win32 target, and in
//! `target/bc45-libs/win64/` for `--target win64` (both stable across runs,
//! git-ignored). RailC and any other OWL app link these via their `mdbcc.toml`
//! `libs` list — no Borland-built OMF library is ever consumed.
//!
//! This is a faithful Rust port of the previously git-ignored campaign scripts
//! `wrk_probe/resweep_rtl.ps1` (RTL + BIDS) and the OWL/streams half of
//! `wrk_probe/closure_railc.ps1`. All translation units compile
//! `-c -m32 -D__WIN32__` (or `-m64` under `--target win64`, additionally with the
//! static-dispatcher OWL overlay + `include64/` ABI headers, materialised into
//! `target/owl-overlay-win64/` by applying `wrk_owl_win64/patches/*.patch` to
//! the user's own BC4.52 sources — see `mdbcc::overlay`);
//! per-unit include sets and the `WINVER` overrides mirror those scripts
//! exactly. The Win64 recipe is the one validated by
//! `tests/railc_source_slice.rs::railc_source_built_dependency_slice_links_win64`.
//!
//! ## Inputs
//! - BC4.52 source tree. Resolved from `$MDBCC_BC45_ROOT`, else the first
//!   existing of `<repo>/wrk_oracle/bc452/BC45` or `C:\tmp\bc45`. The tree is
//!   third-party/copyrighted and git-ignored, so when none is present this
//!   binary **skips loudly and exits 0** — a plain `cargo build` is never
//!   broken by its absence.
//! - The release `bcc`/`mdar` next to this executable (build them first).
//!
//! A coarse fingerprint (compiler + source/header trees) is stamped under the
//! output dir; an unchanged fingerprint with all four archives present is a
//! no-op, so the step is cheap to chain after every toolchain build.

use mdbcc::overlay;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::UNIX_EPOCH;

/// Target architecture for the dependency libraries. `Win32` is the historical
/// default (`-m32`, output in `target/bc45-libs/`); `Win64` (`-m64`) builds the
/// same OWL/streams/RTL/BIDS set with the materialised static-dispatcher OWL
/// overlay + `include64/` pointer-width header overlay, landing in
/// `target/bc45-libs/win64/`. The two are fully isolated (separate object dirs,
/// archives, and fingerprints), so building one never disturbs the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Win32,
    Win64,
}

impl Target {
    /// The `bcc` codegen flag for this target.
    fn flag(self) -> &'static str {
        match self {
            Target::Win32 => "-m32",
            Target::Win64 => "-m64",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Target::Win32 => "win32",
            Target::Win64 => "win64",
        }
    }
}

/// Curated iostreams slice, mirroring `closure_railc.ps1`'s `$streamNames`.
/// Each name `N` maps to `SOURCE/RTL/SOURCE/IOSTREAM/N.CPP` → member `N.o`.
const STREAM_NAMES: &[&str] = &[
    "IOFSCTR1", "IOFSDTR", "FSCTR1", "FSDTR", "FSOPEN", "FSCLOSE", "IOSTCTR2", "IOSTDTR1",
    "ISTCTR1", "ISTCTR2", "ISTDTR1", "OSTCTR1", "OSTDTR1", "STCTR1", "STINIT", "STDTR", "STSETST",
    "STCLEAR", "STBCTR1", "STBDTR", "STBDNEXT", "STBDSGTN", "FSBCTR1", "FSBDTR", "FSBOPEN",
    "FSBCLOSE", "FSBUFLOW", "FSBOFLOW", "FSBSKOFF", "FSBSYNC", "FSBSBUF", "ISTGLINE", "ISTDIPFX",
    "ISRCTR2", "ISRDTR", "SRCTR1", "SRDTR", "SRBCTR6", "SRBDTR", "SRBINIT", "SRBUFLOW", "SRBOFLOW",
    "SRBSKOFF", "SRBSYNC", "SRBSBUF", "SRBDALC", "OSRCTR1", "OSRDTR",
];

/// RTL depth-3 layout: each category directory may hold these target subdirs.
const RTL_SUBS: &[&str] = &["COMMON32", "WIN32", "WINDOWS"];

/// Release `bcc`/`mdar`, located next to this executable.
struct Tools {
    bcc: PathBuf,
    mdar: PathBuf,
}

/// Resolved input/output layout for one build.
struct Layout {
    repo: PathBuf,
    out_dir: PathBuf,
    bc45_root: PathBuf,
    target: Target,
    /// Win64 only: the *materialised* static-dispatcher OWL overlay dir, built
    /// by `mdbcc::overlay` from `wrk_owl_win64/patches/` plus the user's own
    /// BC4.52 tree. `None` for Win32. Never the repo's `wrk_owl_win64/` — that
    /// holds the patches, not the patched sources.
    owl_overlay: Option<PathBuf>,
}

impl Layout {
    fn include(&self) -> PathBuf {
        self.bc45_root.join("INCLUDE")
    }
    fn owl_src(&self) -> PathBuf {
        self.bc45_root.join("SOURCE").join("OWL")
    }
    fn rtl_src(&self) -> PathBuf {
        self.bc45_root.join("SOURCE").join("RTL").join("SOURCE")
    }
    fn rtl_inc(&self) -> PathBuf {
        self.bc45_root.join("SOURCE").join("RTL").join("RTLINC")
    }
    fn bids_src(&self) -> PathBuf {
        self.bc45_root.join("SOURCE").join("CLASSLIB")
    }
    fn iostream_src(&self) -> PathBuf {
        self.rtl_src().join("IOSTREAM")
    }
    /// Win64 only: the `include64/` pointer-width header overlay, prepended ahead
    /// of the stock Borland headers on every TU so the 64-bit
    /// `WPARAM`/`LPARAM`/`LRESULT` (and the dispatch layer) are seen coherently
    /// slice-wide (the non-virtual cross-TU dispatch mangling demands one ABI view).
    fn overlay_inc(&self) -> Option<PathBuf> {
        self.owl_overlay.as_ref().map(|d| d.join("include64"))
    }
    /// `[INCLUDE]` (Win64: `[include64, INCLUDE]`) — OWL and BIDS compile against
    /// the public headers only.
    fn inc(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        dirs.extend(self.overlay_inc());
        dirs.push(self.include());
        dirs
    }
    /// `[INCLUDE, RTLINC/COMMON32, RTLINC/WIN32, RTLINC]` (Win64: prefixed with
    /// `include64`) — RTL and iostreams also see the private RTL headers.
    fn sinc(&self) -> Vec<PathBuf> {
        let rtl_inc = self.rtl_inc();
        let mut dirs = Vec::new();
        dirs.extend(self.overlay_inc());
        dirs.push(self.include());
        dirs.push(rtl_inc.join("COMMON32"));
        dirs.push(rtl_inc.join("WIN32"));
        dirs.push(rtl_inc);
        dirs
    }
    fn rtlshim(&self) -> PathBuf {
        self.repo.join("wrk_rtlshim").join("rtlshim.c")
    }
    fn rtlio(&self) -> PathBuf {
        self.repo.join("wrk_rtlshim").join("rtlio.c")
    }
}

/// Which archive a compile job contributes to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Owl,
    Streams,
    Rtl,
    Bids,
}

impl Group {
    fn label(self) -> &'static str {
        match self {
            Group::Owl => "owl    ",
            Group::Streams => "streams",
            Group::Rtl => "rtl    ",
            Group::Bids => "bids   ",
        }
    }
}

/// One translation unit to compile. Every job writes a distinct object path, so
/// the whole set runs concurrently with no inter-job ordering or contention.
struct Job {
    group: Group,
    src: PathBuf,
    obj: PathBuf,
    includes: Arc<Vec<PathBuf>>,
    extra: Vec<String>,
    required: bool,
}

fn main() -> ExitCode {
    let target = match parse_target(std::env::args().skip(1)) {
        Ok(target) => target,
        Err(msg) => {
            eprintln!("build_bc45_libs: error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let tools = match resolve_tools() {
        Ok(tools) => tools,
        Err(msg) => {
            eprintln!("build_bc45_libs: error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let (repo, base_out) = match resolve_repo_and_out() {
        Ok(pair) => pair,
        Err(msg) => {
            eprintln!("build_bc45_libs: error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    // Sibling of `bc45-libs/` under `target/`: the generated Win64 OWL overlay.
    let overlay_dir = base_out.with_file_name("owl-overlay-win64");
    // Win64 lands in a `win64/` subdir so the two targets' archives, object
    // trees, and fingerprints never collide — building one never disturbs the other.
    let out_dir = match target {
        Target::Win32 => base_out,
        Target::Win64 => base_out.join("win64"),
    };

    let Some(bc45_root) = overlay::resolve_bc45_root(&repo) else {
        println!(
            "build_bc45_libs: BC4.52 source not found (set $MDBCC_BC45_ROOT, or place it at \
             C:\\tmp\\bc45 or {}). Skipping dependency-library build.",
            repo.join("wrk_oracle").join("bc452").join("BC45").display()
        );
        return ExitCode::SUCCESS;
    };
    // Win64: build the patched OWL sources from `wrk_owl_win64/patches/` and the
    // user's own BC4.52 tree. The repository ships only mdbcc's diffs, so the
    // overlay has to be generated before any Win64 job can compile it.
    let owl_overlay = match target {
        Target::Win32 => None,
        Target::Win64 => match overlay::materialize(&repo, &bc45_root, &overlay_dir) {
            Ok(dir) => Some(dir),
            Err(e) => {
                eprintln!("build_bc45_libs: error: cannot build the Win64 OWL overlay: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    let layout = Layout {
        repo,
        out_dir,
        bc45_root,
        target,
        owl_overlay,
    };

    println!("build_bc45_libs: target  = {}", layout.target.as_str());
    println!("build_bc45_libs: source  = {}", layout.bc45_root.display());
    if let Some(overlay) = &layout.owl_overlay {
        println!("build_bc45_libs: overlay = {}", overlay.display());
    }
    println!("build_bc45_libs: output  = {}", layout.out_dir.display());

    let archives = [
        layout.out_dir.join("mdowl.lib"),
        layout.out_dir.join("mdstreams.lib"),
        layout.out_dir.join("mdcw32.lib"),
        layout.out_dir.join("mdbids.lib"),
    ];
    let fingerprint = compute_fingerprint(&tools, &layout);
    if up_to_date(&layout.out_dir, fingerprint, &archives) {
        println!("build_bc45_libs: up to date (fingerprint {fingerprint:016x}); nothing to do.");
        return ExitCode::SUCCESS;
    }

    if let Err(msg) = build_all(&tools, &layout) {
        eprintln!("build_bc45_libs: error: {msg}");
        return ExitCode::FAILURE;
    }

    if let Err(msg) = write_stamp(&layout.out_dir, fingerprint) {
        eprintln!("build_bc45_libs: warning: could not write fingerprint stamp: {msg}");
    }
    for lib in &archives {
        match fs::metadata(lib) {
            Ok(meta) => println!("build_bc45_libs: {:>9} B  {}", meta.len(), lib.display()),
            Err(e) => {
                eprintln!(
                    "build_bc45_libs: error: missing archive {}: {e}",
                    lib.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }
    println!("build_bc45_libs: done.");
    ExitCode::SUCCESS
}

/// Build all four archives: reset the object directories, compile every
/// translation unit (in parallel — the units are independent), then archive
/// each group. Per-unit compile failures are tolerated (symbol-driven linking
/// pulls only what an app needs); the two RTL shim units are required.
fn build_all(tools: &Tools, layout: &Layout) -> Result<(), String> {
    let obj_root = layout.out_dir.join("obj");
    let owl_obj = obj_root.join("owl");
    let streams_obj = obj_root.join("streams");
    let rtl_obj = obj_root.join("rtl");
    let bids_obj = obj_root.join("bids");
    for dir in [&owl_obj, &streams_obj, &rtl_obj, &bids_obj] {
        reset_dir(dir, &layout.out_dir)?;
    }
    fs::create_dir_all(&layout.out_dir)
        .map_err(|e| format!("create {}: {e}", layout.out_dir.display()))?;

    let inc = Arc::new(layout.inc());
    let sinc = Arc::new(layout.sinc());
    let mut jobs = Vec::new();
    jobs.extend(owl_jobs(layout, &owl_obj, &inc));
    jobs.extend(streams_jobs(layout, &streams_obj, &sinc));
    jobs.extend(rtl_jobs(layout, &rtl_obj, &inc, &sinc));
    jobs.extend(bids_jobs(layout, &bids_obj, &inc));

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    println!(
        "build_bc45_libs: compiling {} translation units across {threads} threads...",
        jobs.len()
    );
    let results = run_jobs(tools, layout.target, &jobs, threads)?;
    for group in [Group::Owl, Group::Streams, Group::Rtl, Group::Bids] {
        let total = results.iter().filter(|(g, _)| *g == group).count();
        let ok = results.iter().filter(|(g, o)| *g == group && *o).count();
        println!(
            "build_bc45_libs: {} ok={ok} skip={}",
            group.label(),
            total - ok
        );
    }

    archive(tools, &owl_obj, &layout.out_dir.join("mdowl.lib"))?;
    archive(tools, &streams_obj, &layout.out_dir.join("mdstreams.lib"))?;
    archive(tools, &rtl_obj, &layout.out_dir.join("mdcw32.lib"))?;
    archive(tools, &bids_obj, &layout.out_dir.join("mdbids.lib"))?;
    Ok(())
}

/// Run every job across `threads` workers pulling from a shared cursor. Returns
/// `(group, succeeded)` per job; errors only if a *required* unit failed.
fn run_jobs(
    tools: &Tools,
    target: Target,
    jobs: &[Job],
    threads: usize,
) -> Result<Vec<(Group, bool)>, String> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(Group, bool)>> = Mutex::new(Vec::with_capacity(jobs.len()));
    let required_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| {
                loop {
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    let Some(job) = jobs.get(idx) else {
                        break;
                    };
                    let extra: Vec<&str> = job.extra.iter().map(String::as_str).collect();
                    let outcome = compile(
                        tools,
                        target,
                        &job.src,
                        &job.obj,
                        job.includes.as_slice(),
                        &extra,
                    );
                    if job.required
                        && let Err(e) = &outcome
                    {
                        required_failures
                            .lock()
                            .unwrap()
                            .push(format!("{}: {e}", job.src.display()));
                    }
                    results.lock().unwrap().push((job.group, outcome.is_ok()));
                }
            });
        }
    });
    let failures = required_failures.into_inner().unwrap();
    if !failures.is_empty() {
        return Err(format!(
            "required compile(s) failed:\n  {}",
            failures.join("\n  ")
        ));
    }
    Ok(results.into_inner().unwrap())
}

/// OWL framework: every `*.CPP` in `SOURCE/OWL`, public headers only. Units that
/// do not compile are skipped (symbol-driven linking pulls only what the app
/// needs), mirroring `closure_railc.ps1`.
fn owl_jobs(layout: &Layout, obj_dir: &Path, inc: &Arc<Vec<PathBuf>>) -> Vec<Job> {
    let overlay = layout.owl_overlay.clone();
    cpp_sources(&layout.owl_src())
        .into_iter()
        .map(|src| {
            // Win64 (MDBCC-01): build OWL/WINDOW/DISPATCH/DIALOG from the patched
            // static-dispatcher copies instead of the oracle sources (name-
            // preserving), mirroring the source-slice harness's `member_source`.
            let stem = file_stem(&src).to_ascii_uppercase();
            let src = match &overlay {
                Some(dir) if matches!(stem.as_str(), "OWL" | "WINDOW" | "DISPATCH" | "DIALOG") => {
                    dir.join(format!("{stem}.CPP"))
                }
                _ => src,
            };
            let extra = if stem == "DIB" {
                // DIB.CPP is a Borland-sectioned OWL source. The full TU still
                // overflows mdbcc's compiler stack in the bitmap read/write
                // sections, but SECTION=1 provides TDib::ToClipboard, which
                // RailC and the OWL clipboard helpers need.
                vec!["SECTION=1".to_string()]
            } else {
                Vec::new()
            };
            Job {
                group: Group::Owl,
                obj: obj_dir.join(format!("{}.o", file_stem(&src))),
                src,
                includes: Arc::clone(inc),
                extra,
                required: false,
            }
        })
        .collect()
}

/// Curated iostreams slice: the 48 named units, RTL include set.
fn streams_jobs(layout: &Layout, obj_dir: &Path, sinc: &Arc<Vec<PathBuf>>) -> Vec<Job> {
    let iostream = layout.iostream_src();
    STREAM_NAMES
        .iter()
        .map(|name| Job {
            group: Group::Streams,
            src: iostream.join(format!("{name}.CPP")),
            obj: obj_dir.join(format!("{name}.o")),
            includes: Arc::clone(sinc),
            extra: Vec::new(),
            required: false,
        })
        .collect()
}

/// C/C++ RTL, mirroring `resweep_rtl.ps1`:
/// - depth-3: `CAT/{COMMON32,WIN32,WINDOWS}/*.{C,CPP}` → member `CAT_SUB_file.o`
/// - depth-2: `CAT/*.{C,CPP}` (except `EASYWIN`)        → member `CAT__file.o`
/// - `MISC/WIN32/{ERRORMSG,GP}.C` get `-DWINVER=0x030A` (Bug E, INCL_USER)
/// - `wrk_rtlshim/{rtlshim,rtlio}.c` (both required) replace Borland's `HEAP.C` /
///   low-level io with process-heap-backed equivalents.
fn rtl_jobs(
    layout: &Layout,
    obj_dir: &Path,
    inc: &Arc<Vec<PathBuf>>,
    sinc: &Arc<Vec<PathBuf>>,
) -> Vec<Job> {
    let rtl_src = layout.rtl_src();
    let mut jobs = Vec::new();

    // Pass 1: depth-3 CAT/SUB. The two INCL_USER units carry the WINVER define
    // directly (their depth-3 object is the one that lands in the archive).
    for cat in subdirs(&rtl_src) {
        let cat_name = file_name(&cat);
        for sub in RTL_SUBS {
            let dir = cat.join(sub);
            if !dir.is_dir() {
                continue;
            }
            for src in c_or_cpp_sources(&dir) {
                let name = file_name(&src);
                let extra = rtl_extra_defines(&cat_name, sub, &name);
                jobs.push(Job {
                    group: Group::Rtl,
                    obj: obj_dir.join(rtl_depth3_obj_name(&cat_name, sub, &name)),
                    src,
                    includes: Arc::clone(sinc),
                    extra,
                    required: false,
                });
            }
        }
    }

    // Pass 2: depth-2 CAT direct children (EASYWIN excluded).
    for cat in subdirs(&rtl_src) {
        let cat_name = file_name(&cat);
        if cat_name.eq_ignore_ascii_case("EASYWIN") {
            continue;
        }
        for src in c_or_cpp_sources(&cat) {
            jobs.push(Job {
                group: Group::Rtl,
                obj: obj_dir.join(rtl_depth2_obj_name(&cat_name, &file_name(&src))),
                src,
                includes: Arc::clone(sinc),
                extra: Vec::new(),
                required: false,
            });
        }
    }

    // Heap/io shim — required (replaces Borland's HEAP.C / low-level io).
    jobs.push(Job {
        group: Group::Rtl,
        src: layout.rtlshim(),
        obj: obj_dir.join("rtlshim.o"),
        includes: Arc::clone(inc),
        extra: Vec::new(),
        required: true,
    });
    jobs.push(Job {
        group: Group::Rtl,
        src: layout.rtlio(),
        obj: obj_dir.join("rtlio.o"),
        includes: Arc::clone(sinc),
        extra: Vec::new(),
        required: true,
    });
    jobs
}

/// BIDS container library: every `*.CPP` in `SOURCE/CLASSLIB`, public headers.
fn bids_jobs(layout: &Layout, obj_dir: &Path, inc: &Arc<Vec<PathBuf>>) -> Vec<Job> {
    cpp_sources(&layout.bids_src())
        .into_iter()
        .map(|src| Job {
            group: Group::Bids,
            obj: obj_dir.join(format!("{}.o", file_stem(&src))),
            src,
            includes: Arc::clone(inc),
            extra: Vec::new(),
            required: false,
        })
        .collect()
}

fn rtl_extra_defines(cat: &str, sub: &str, name: &str) -> Vec<String> {
    let needs_winver = (cat.eq_ignore_ascii_case("MISC")
        && sub.eq_ignore_ascii_case("WIN32")
        && (name.eq_ignore_ascii_case("ERRORMSG.C") || name.eq_ignore_ascii_case("GP.C")))
        || (cat.eq_ignore_ascii_case("EXCEPT")
            && sub.eq_ignore_ascii_case("COMMON32")
            && name.eq_ignore_ascii_case("EXCEPT.C"));

    if needs_winver {
        vec!["WINVER=0x030A".to_string()]
    } else {
        Vec::new()
    }
}

/// Compile one TU `-c <target-flag> -D__WIN32__` plus `extra_defines` and
/// `-I includes`. `-D__WIN32__` is retained for both targets (the Borland
/// flat-model macro). Output is suppressed; on failure the (possibly partial)
/// object is removed and the captured stderr is returned so required callers can
/// surface it.
fn compile(
    tools: &Tools,
    target: Target,
    src: &Path,
    obj: &Path,
    includes: &[PathBuf],
    extra_defines: &[&str],
) -> Result<(), String> {
    let mut cmd = Command::new(&tools.bcc);
    cmd.arg("-c").arg(target.flag()).arg("-D__WIN32__");
    for define in extra_defines {
        cmd.arg(format!("-D{define}"));
    }
    for inc in includes {
        cmd.arg("-I").arg(inc);
    }
    cmd.arg(src).arg("-o").arg(obj);
    cmd.stdin(Stdio::null());
    let output = cmd
        .output()
        .map_err(|e| format!("spawn {}: {e}", tools.bcc.display()))?;
    if output.status.success() && obj.is_file() {
        Ok(())
    } else {
        let _ = fs::remove_file(obj);
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Archive every `*.o` in `obj_dir` (sorted by name) into `out_lib` via `mdar`.
/// `mdar` runs with `obj_dir` as its CWD so member names are the bare file
/// names — matching the campaign scripts and the source-slice harness.
fn archive(tools: &Tools, obj_dir: &Path, out_lib: &Path) -> Result<(), String> {
    let mut objs: Vec<OsString> = fs::read_dir(obj_dir)
        .map_err(|e| format!("read {}: {e}", obj_dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| has_ext(p, "o"))
        .filter_map(|p| p.file_name().map(OsString::from))
        .collect();
    objs.sort();
    if objs.is_empty() {
        return Err(format!("no objects to archive in {}", obj_dir.display()));
    }
    let out_abs = absolute_from(obj_dir, out_lib);
    let status = Command::new(&tools.mdar)
        .current_dir(obj_dir)
        .arg("-o")
        .arg(&out_abs)
        .args(&objs)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("spawn {}: {e}", tools.mdar.display()))?;
    if status.success() && out_lib.is_file() {
        Ok(())
    } else {
        Err(format!("mdar failed for {}", out_lib.display()))
    }
}

// ---- argument / input / output resolution -----------------------------------

/// Parse `--target win64|win32` (default `win32`) from the CLI args. Accepts
/// both `--target VALUE` and `--target=VALUE`. Any other argument, or an unknown
/// value, is an error so a typo never silently builds the wrong architecture.
fn parse_target(mut args: impl Iterator<Item = String>) -> Result<Target, String> {
    let mut target = Target::Win32;
    while let Some(arg) = args.next() {
        let value = if let Some(v) = arg.strip_prefix("--target=") {
            v.to_string()
        } else if arg == "--target" {
            args.next()
                .ok_or_else(|| "--target requires a value (win32|win64)".to_string())?
        } else {
            return Err(format!(
                "unknown argument '{arg}' (expected --target win32|win64)"
            ));
        };
        target = match value.as_str() {
            "win32" => Target::Win32,
            "win64" => Target::Win64,
            other => {
                return Err(format!(
                    "unknown target '{other}' (expected win32 or win64)"
                ));
            }
        };
    }
    Ok(target)
}

fn resolve_tools() -> Result<Tools, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "executable has no parent directory".to_string())?;
    let bcc = dir.join(exe_name("bcc"));
    let mdar = dir.join(exe_name("mdar"));
    for (tool, path) in [("bcc", &bcc), ("mdar", &mdar)] {
        if !path.is_file() {
            return Err(format!(
                "missing {tool} at {}; run `cargo build --release --bins` first",
                path.display()
            ));
        }
    }
    Ok(Tools { bcc, mdar })
}

/// `(repo_root, output_dir)`. Tools live in `<repo>/target/<profile>/`, so the
/// repo root is two levels up and the output dir is `<repo>/target/bc45-libs`.
fn resolve_repo_and_out() -> Result<(PathBuf, PathBuf), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let profile_dir = exe
        .parent()
        .ok_or_else(|| "executable has no parent directory".to_string())?;
    let target_dir = profile_dir
        .parent()
        .ok_or_else(|| "cannot locate target/ directory".to_string())?;
    let repo = target_dir
        .parent()
        .ok_or_else(|| "cannot locate repository root".to_string())?
        .to_path_buf();
    let out_dir = target_dir.join("bc45-libs");
    Ok((repo, out_dir))
}

// ---- fingerprint / stamp ----------------------------------------------------

fn compute_fingerprint(tools: &Tools, layout: &Layout) -> u64 {
    let rtl_root = layout.bc45_root.join("SOURCE").join("RTL");
    let owl_src = layout.owl_src();
    let bids_src = layout.bids_src();
    let include = layout.include();
    let mut roots: Vec<&Path> = vec![
        rtl_root.as_path(), // RTL SOURCE + RTLINC headers
        owl_src.as_path(),  // OWL framework source
        bids_src.as_path(), // BIDS source
        include.as_path(),  // public headers
    ];
    // Win64: fold the overlay's *sources* — `wrk_owl_win64/` (the patches plus the
    // mdbcc-authored headers) — into the hash, so editing a patch or an ABI header
    // invalidates the cached build. Never the generated dir: it is rewritten on
    // every run, so hashing it would defeat the cache entirely.
    let overlay_src = overlay::source_dir(&layout.repo);
    if layout.owl_overlay.is_some() {
        roots.push(overlay_src.as_path());
    }
    let mut files = vec![
        layout.rtlshim(),
        layout.rtlio(),
        tools.bcc.clone(),
        tools.mdar.clone(),
    ];
    if let Ok(exe) = std::env::current_exe() {
        files.push(exe);
    }
    fingerprint(&roots, &files)
}

fn up_to_date(out_dir: &Path, fingerprint: u64, archives: &[PathBuf]) -> bool {
    if !archives.iter().all(|p| p.is_file()) {
        return false;
    }
    match fs::read_to_string(out_dir.join(".fingerprint")) {
        Ok(text) => text.trim() == format!("{fingerprint:016x}"),
        Err(_) => false,
    }
}

fn write_stamp(out_dir: &Path, fingerprint: u64) -> Result<(), String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;
    fs::write(
        out_dir.join(".fingerprint"),
        format!("{fingerprint:016x}\n"),
    )
    .map_err(|e| format!("write stamp: {e}"))
}

/// FNV-1a/64 over every file (path, len, mtime-secs) found under `roots`, plus
/// the explicit `files`. Sorted first so the hash is order-independent.
fn fingerprint(roots: &[&Path], files: &[PathBuf]) -> u64 {
    let mut entries: Vec<(String, u64, u64)> = Vec::new();
    for root in roots {
        collect_files(root, &mut entries);
    }
    for file in files {
        push_file(file, &mut entries);
    }
    entries.sort();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut mix = |bytes: &[u8]| {
        for b in bytes {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for (path, len, mtime) in &entries {
        mix(path.as_bytes());
        mix(&len.to_le_bytes());
        mix(&mtime.to_le_bytes());
    }
    hash
}

fn collect_files(dir: &Path, out: &mut Vec<(String, u64, u64)>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => collect_files(&path, out),
            Ok(ft) if ft.is_file() => push_file(&path, out),
            _ => {}
        }
    }
}

fn push_file(path: &Path, out: &mut Vec<(String, u64, u64)>) {
    if let Ok(meta) = fs::metadata(path) {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push((path.to_string_lossy().into_owned(), meta.len(), mtime));
    }
}

// ---- small path helpers -----------------------------------------------------

fn rtl_depth3_obj_name(cat: &str, sub: &str, file_name: &str) -> String {
    format!("{cat}_{sub}_{file_name}.o")
}

fn rtl_depth2_obj_name(cat: &str, file_name: &str) -> String {
    format!("{cat}__{file_name}.o")
}

/// Files directly in `dir` whose extension is `.CPP` (case-insensitive), sorted.
fn cpp_sources(dir: &Path) -> Vec<PathBuf> {
    sources_matching(dir, &["cpp"])
}

/// Files directly in `dir` whose extension is `.C` or `.CPP`, sorted.
fn c_or_cpp_sources(dir: &Path) -> Vec<PathBuf> {
    sources_matching(dir, &["c", "cpp"])
}

fn sources_matching(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .map(|e| e.path())
            .filter(|p| exts.iter().any(|ext| has_ext(p, ext)))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

fn absolute_from(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Remove and recreate `dir`, refusing to touch anything outside `guard`.
fn reset_dir(dir: &Path, guard: &Path) -> Result<(), String> {
    if !dir.starts_with(guard) {
        return Err(format!(
            "refusing to reset {} outside {}",
            dir.display(),
            guard.display()
        ));
    }
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| format!("reset {}: {e}", dir.display()))?;
    }
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_slice_has_48_units() {
        assert_eq!(STREAM_NAMES.len(), 48);
    }

    #[test]
    fn target_flags_match_bcc_codegen_switch() {
        assert_eq!(Target::Win32.flag(), "-m32");
        assert_eq!(Target::Win64.flag(), "-m64");
        assert_eq!(Target::Win32.as_str(), "win32");
        assert_eq!(Target::Win64.as_str(), "win64");
    }

    #[test]
    fn parse_target_defaults_to_win32_and_parses_both_forms() {
        let parse = |args: &[&str]| parse_target(args.iter().map(|s| s.to_string()));
        assert_eq!(parse(&[]).unwrap(), Target::Win32);
        assert_eq!(parse(&["--target", "win64"]).unwrap(), Target::Win64);
        assert_eq!(parse(&["--target=win64"]).unwrap(), Target::Win64);
        assert_eq!(parse(&["--target", "win32"]).unwrap(), Target::Win32);
        assert!(parse(&["--target", "wat"]).is_err());
        assert!(parse(&["--target"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
    }

    #[test]
    fn rtl_member_names_match_slice_convention() {
        // Mirrors tests/corpus/railc/source_slice.tsv member names.
        assert_eq!(
            rtl_depth3_obj_name("CSTRINGS", "COMMON32", "STRCSPN.C"),
            "CSTRINGS_COMMON32_STRCSPN.C.o"
        );
        assert_eq!(
            rtl_depth3_obj_name("MISC", "WIN32", "ERRORMSG.C"),
            "MISC_WIN32_ERRORMSG.C.o"
        );
        assert_eq!(
            rtl_depth2_obj_name("EXCEPT", "XALLOC.CPP"),
            "EXCEPT__XALLOC.CPP.o"
        );
        assert_eq!(
            rtl_depth2_obj_name("IOSTREAM", "FSBATTCH.CPP"),
            "IOSTREAM__FSBATTCH.CPP.o"
        );
    }

    #[test]
    fn rtl_except_c_gets_winver_define() {
        let dir =
            std::env::temp_dir().join(format!("mdbcc_bc45_except_job_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let except_dir = dir
            .join("bc45")
            .join("SOURCE")
            .join("RTL")
            .join("SOURCE")
            .join("EXCEPT")
            .join("COMMON32");
        fs::create_dir_all(&except_dir).unwrap();
        fs::write(except_dir.join("EXCEPT.C"), b"").unwrap();

        let layout = Layout {
            repo: dir.join("repo"),
            out_dir: dir.join("out"),
            bc45_root: dir.join("bc45"),
            target: Target::Win32,
            owl_overlay: None,
        };
        let inc = Arc::new(layout.inc());
        let sinc = Arc::new(layout.sinc());
        let jobs = rtl_jobs(&layout, &dir.join("obj"), &inc, &sinc);

        let except = jobs
            .iter()
            .find(|job| job.src.ends_with("EXCEPT.C"))
            .expect("EXCEPT.C job");
        assert_eq!(except.extra, ["WINVER=0x030A"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn has_ext_is_case_insensitive() {
        assert!(has_ext(Path::new("A.C"), "c"));
        assert!(has_ext(Path::new("a.cpp"), "cpp"));
        assert!(has_ext(Path::new("WINDOW.CPP"), "cpp"));
        assert!(!has_ext(Path::new("WINDOW.CPP"), "c"));
        assert!(!has_ext(Path::new("readme"), "c"));
    }

    #[test]
    fn fingerprint_is_order_independent_and_change_sensitive() {
        let dir = std::env::temp_dir().join("mdbcc_bc45_fp_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        fs::write(dir.join("a").join("x.c"), b"one").unwrap();
        fs::write(dir.join("b").join("y.c"), b"two").unwrap();

        let a = dir.join("a");
        let b = dir.join("b");
        let fp1 = fingerprint(&[a.as_path(), b.as_path()], &[]);
        let fp2 = fingerprint(&[b.as_path(), a.as_path()], &[]);
        assert_eq!(fp1, fp2, "root order must not change the fingerprint");

        fs::write(dir.join("a").join("x.c"), b"one-changed-longer").unwrap();
        let fp3 = fingerprint(&[a.as_path(), b.as_path()], &[]);
        assert_ne!(fp1, fp3, "content/size change must change the fingerprint");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_dir_refuses_outside_guard() {
        let guard = std::env::temp_dir().join("mdbcc_guard_root");
        let outside = std::env::temp_dir().join("mdbcc_guard_sibling");
        assert!(reset_dir(&outside, &guard).is_err());
    }
}
