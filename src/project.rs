use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::codegen::target::TargetKind;
use crate::coff;
use crate::compile::compile_to_object_reported;
use crate::link::{self, Input, LinkOpts, Subsystem};
use crate::pp::{DefaultResolver, IncludeResolver, SearchPathResolver};
use crate::progress::{Painter, Reporter};
use crate::rc;

const CONFIG_FILE: &str = "mdbcc.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectError {
    message: String,
}

impl ProjectError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn at(path: &Path, line: usize, message: impl AsRef<str>) -> Self {
        Self::new(format!("{}:{}: {}", path.display(), line, message.as_ref()))
    }
}

impl fmt::Display for ProjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProjectError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTarget {
    Win64,
    Win32,
}

impl ProjectTarget {
    fn target_kind(self) -> TargetKind {
        match self {
            ProjectTarget::Win64 => TargetKind::Win64,
            ProjectTarget::Win32 => TargetKind::Win32,
        }
    }

    fn machine(self) -> coff::Machine {
        match self {
            ProjectTarget::Win64 => coff::Machine::Amd64,
            ProjectTarget::Win32 => coff::Machine::I386,
        }
    }

    fn image_base(self) -> u64 {
        match self {
            ProjectTarget::Win64 => 0x1_4000_0000,
            ProjectTarget::Win32 => 0x0040_0000,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ProjectTarget::Win64 => "win64",
            ProjectTarget::Win32 => "win32",
        }
    }

    /// Human-facing architecture label that spells out the bit width, so "32 vs
    /// 64" is unmistakable in the build banner (the bare `win64`/`win32` name
    /// assumes the reader knows the convention).
    pub fn arch_label(self) -> &'static str {
        match self {
            ProjectTarget::Win64 => "64-bit x86-64",
            ProjectTarget::Win32 => "32-bit x86",
        }
    }
}

impl fmt::Display for ProjectTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceProfile {
    Brc32,
    Bc45,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceInput {
    Rc(PathBuf),
    Res(PathBuf),
}

impl ResourceInput {
    fn path(&self) -> &Path {
        match self {
            ResourceInput::Rc(path) | ResourceInput::Res(path) => path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectManifest {
    pub manifest_path: PathBuf,
    pub manifest_dir: PathBuf,
    pub name: Option<String>,
    pub sources: Vec<PathBuf>,
    pub output: PathBuf,
    pub target: ProjectTarget,
    pub subsystem: Option<Subsystem>,
    /// High-priority include directories searched BEFORE `include_dirs`. Used
    /// to overlay target-specific headers — notably the Win64 ABI overlay
    /// (`include64/` with pointer-width `WPARAM`/`LPARAM`/`LRESULT` + the
    /// `*Ptr` thunk prototypes) prepended ahead of the stock Borland headers so
    /// a `-m64` build sees one coherent ABI view. Empty for a plain build.
    pub overlay_dirs: Vec<PathBuf>,
    pub include_dirs: Vec<PathBuf>,
    pub defines: Vec<(String, String)>,
    pub resources: Vec<ResourceInput>,
    pub resource_profile: ResourceProfile,
    pub objects: Vec<PathBuf>,
    pub libs: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildReport {
    pub manifest_path: PathBuf,
    pub output: PathBuf,
    pub target: ProjectTarget,
    pub subsystem: Subsystem,
    pub source_count: usize,
    pub resource_count: usize,
    pub object_count: usize,
    pub lib_count: usize,
    /// Total source lines fed through the compiler across all sources.
    pub lines_total: u64,
    /// Functions whose codegen was deferred (S4.2g/S4.2h), summed over sources.
    pub notes_deferred: usize,
    /// Unreachable inline functions pruned (S4.2q), summed over sources.
    pub notes_pruned: usize,
    /// Build-log path, present only when at least one note was emitted.
    pub log_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    Help(String),
    Version(String),
    Build(BuildReport),
}

#[derive(Debug, Clone)]
struct RawKv {
    key: String,
    value: RawValue,
    line: usize,
}

#[derive(Debug, Clone)]
enum RawValue {
    String(String),
    StringArray(Vec<String>),
}

#[derive(Debug, Default)]
struct ParsedToml {
    package: Vec<RawKv>,
}

pub fn find_config(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(CONFIG_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn run_cli(args: &[String], cwd: &Path) -> Result<CliAction, ProjectError> {
    match args {
        [] => {
            let path = find_config(cwd).ok_or_else(|| {
                ProjectError::new(format!(
                    "could not find {CONFIG_FILE} in '{}' or any parent directory",
                    cwd.display()
                ))
            })?;
            build_from_manifest_path(&path).map(CliAction::Build)
        }
        [flag] if flag == "--help" || flag == "-h" => Ok(CliAction::Help(help_text())),
        [flag] if flag == "--version" || flag == "-V" => Ok(CliAction::Version(format!(
            "mdbcc {}",
            env!("CARGO_PKG_VERSION")
        ))),
        [flag, value] if flag == "--config" => {
            let raw = PathBuf::from(value);
            let path = if raw.is_absolute() {
                raw
            } else {
                lexical_normalize(&cwd.join(raw))
            };
            build_from_manifest_path(&path).map(CliAction::Build)
        }
        [flag] if flag == "--config" => Err(ProjectError::new("--config requires a path")),
        [first, ..] if is_build_override(first) => Err(ProjectError::new(format!(
            "unsupported build override '{first}' in manifest-only v1; edit {CONFIG_FILE} or use bcc/mdlink directly"
        ))),
        [first, ..] if first.starts_with('-') => Err(ProjectError::new(format!(
            "unknown option '{first}'; try 'mdbcc --help'"
        ))),
        [first, ..] => Err(ProjectError::new(format!(
            "positional source argument '{first}' is not supported by mdbcc project mode; use bcc for explicit source compilation"
        ))),
    }
}

pub fn help_text() -> String {
    format!(
        "usage: mdbcc [--config PATH]\n\
         \n\
         Builds the project described by {CONFIG_FILE}. With no arguments,\n\
         mdbcc searches the current directory and then parent directories for\n\
         {CONFIG_FILE}. Project mode is manifest-only in v1; use bcc, mdlink,\n\
         mdrc, or mdar for explicit one-off tool invocations.\n\
         \n\
         Options:\n\
           --config PATH   build the specified manifest\n\
           -h, --help      show this help\n\
           -V, --version   show the mdbcc version\n"
    )
}

pub fn build_from_manifest_path(path: &Path) -> Result<BuildReport, ProjectError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ProjectError::new(format!("cannot read '{}': {e}", path.display())))?;
    let manifest = parse_manifest_text(&text, path)?;
    build_manifest(&manifest)
}

pub fn parse_manifest_text(text: &str, path: &Path) -> Result<ProjectManifest, ProjectError> {
    let parsed = parse_toml(text, path)?;
    finalize_manifest(parsed, path)
}

pub fn build_manifest(manifest: &ProjectManifest) -> Result<BuildReport, ProjectError> {
    let target_dir = manifest.manifest_dir.join("target").join("mdbcc");
    let object_dir = target_dir.join("objects");
    let resource_dir = target_dir.join("resources");
    std::fs::create_dir_all(&object_dir).map_err(|e| {
        ProjectError::new(format!(
            "cannot create generated object directory '{}': {e}",
            object_dir.display()
        ))
    })?;
    std::fs::create_dir_all(&resource_dir).map_err(|e| {
        ProjectError::new(format!(
            "cannot create generated resource directory '{}': {e}",
            resource_dir.display()
        ))
    })?;

    // Route the (often huge) note: forest into a build log and show a live
    // per-file progress line instead of letting it drown the terminal.
    let log_path = target_dir.join("build.log");
    let mut log = std::fs::File::create(&log_path).map_err(|e| {
        ProjectError::new(format!(
            "cannot create build log '{}': {e}",
            log_path.display()
        ))
    })?;
    // Announce the target architecture once, up front, so the bit width is
    // unmistakable while the per-file progress streams below. Lives on stderr
    // alongside the progress line; stdout stays clean for the final summary.
    let banner = Painter::stderr();
    eprintln!(
        "{} {} {}",
        banner.dim("compiling for"),
        banner.cyan(manifest.target.as_str()),
        banner.dim(&format!("({})", manifest.target.arch_label())),
    );

    // Translation units are independent — each compiles to its own object, and
    // the link step runs strictly afterwards — so compile them across worker
    // threads. Results are drained in source order, so the link input (and thus
    // the output) is byte-identical to a serial build, and the lowest-index
    // error wins deterministically. `MDBCC_JOBS=1` forces the serial path,
    // which keeps the live per-phase progress line for single-TU debugging.
    let jobs = decide_jobs(manifest.sources.len());
    let (generated_objects, lines_total, notes) = if jobs <= 1 {
        compile_sequential(manifest, &object_dir, &mut log)?
    } else {
        compile_parallel(manifest, &object_dir, &mut log, jobs)?
    };
    drop(log);
    let log_path = if notes.total() > 0 {
        Some(log_path)
    } else {
        let _ = std::fs::remove_file(&log_path);
        None
    };

    let resource_defines = defines_map(&manifest.defines);
    let mut res_inputs: Vec<(String, Vec<u8>)> = Vec::new();
    for (ix, resource) in manifest.resources.iter().enumerate() {
        match resource {
            ResourceInput::Rc(path) => {
                let unit = rc::compile_file(path, &resource_defines)
                    .map_err(|e| ProjectError::new(format!("{}:{e}", path.display())))?;
                let bytes = match manifest.resource_profile {
                    ResourceProfile::Brc32 => rc::write_res(&unit),
                    ResourceProfile::Bc45 => rc::write_res_bc45(&unit),
                };
                let generated_name = generated_file_name(ix, &manifest.manifest_dir, path, "res");
                let out_path = resource_dir.join(generated_name);
                std::fs::write(&out_path, &bytes).map_err(|e| {
                    ProjectError::new(format!(
                        "cannot write generated resource '{}': {e}",
                        out_path.display()
                    ))
                })?;
                res_inputs.push((out_path.display().to_string(), bytes));
            }
            ResourceInput::Res(path) => {
                let bytes = std::fs::read(path).map_err(|e| {
                    ProjectError::new(format!("cannot read resource '{}': {e}", path.display()))
                })?;
                res_inputs.push((path.display().to_string(), bytes));
            }
        }
    }

    let mut prebuilt_objects = Vec::with_capacity(manifest.objects.len());
    let mut prebuilt_object_bytes = Vec::with_capacity(manifest.objects.len());
    for path in &manifest.objects {
        let bytes = std::fs::read(path).map_err(|e| {
            ProjectError::new(format!("cannot read object '{}': {e}", path.display()))
        })?;
        let object = coff::Object::read(&bytes).map_err(|e| {
            ProjectError::new(format!("cannot decode object '{}': {e}", path.display()))
        })?;
        prebuilt_objects.push(object);
        prebuilt_object_bytes.push((path.display().to_string(), bytes));
    }

    let mut lib_inputs = Vec::with_capacity(manifest.libs.len());
    for path in &manifest.libs {
        let bytes = std::fs::read(path).map_err(|e| {
            ProjectError::new(format!("cannot read library '{}': {e}", path.display()))
        })?;
        lib_inputs.push((path.display().to_string(), bytes));
    }

    let subsystem = manifest.subsystem.unwrap_or_else(|| {
        generated_objects
            .iter()
            .chain(prebuilt_objects.iter())
            .map(link::auto_subsystem)
            .find(|s| *s == Subsystem::Gui)
            .unwrap_or(Subsystem::Console)
    });

    let mut inputs = Vec::new();
    for obj in &generated_objects {
        inputs.push(Input::Object(obj));
    }
    for (name, bytes) in prebuilt_object_bytes {
        inputs.push(Input::CoffBytes { name, bytes });
    }
    for (name, bytes) in lib_inputs {
        inputs.push(Input::Archive { name, bytes });
    }
    for (name, bytes) in res_inputs {
        inputs.push(Input::ResFile { name, bytes });
    }

    let opts = LinkOpts {
        machine: manifest.target.machine(),
        subsystem,
        image_base: manifest.target.image_base(),
        ..LinkOpts::default()
    };
    let exe =
        link::link(&inputs, &opts).map_err(|e| ProjectError::new(format!("link failed: {e}")))?;
    if let Some(parent) = manifest
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            ProjectError::new(format!(
                "cannot create output directory '{}': {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(&manifest.output, exe).map_err(|e| {
        ProjectError::new(format!(
            "cannot write output '{}': {e}",
            manifest.output.display()
        ))
    })?;

    Ok(BuildReport {
        manifest_path: manifest.manifest_path.clone(),
        output: manifest.output.clone(),
        target: manifest.target,
        subsystem,
        source_count: manifest.sources.len(),
        resource_count: manifest.resources.len(),
        object_count: manifest.objects.len(),
        lib_count: manifest.libs.len(),
        lines_total,
        notes_deferred: notes.deferred,
        notes_pruned: notes.pruned,
        log_path,
    })
}

/// Number of worker threads for the per-TU compile. `MDBCC_JOBS` overrides the
/// detected core count (clamped to at least 1 and at most the source count);
/// `MDBCC_JOBS=1` forces the serial path. A single-source build is always
/// serial — there is nothing to parallelise.
fn decide_jobs(n_sources: usize) -> usize {
    if n_sources <= 1 {
        return 1;
    }
    if let Some(raw) = std::env::var_os("MDBCC_JOBS")
        && let Some(j) = raw.to_str().and_then(|s| s.trim().parse::<usize>().ok())
    {
        return j.clamp(1, n_sources);
    }
    std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1)
        .clamp(1, n_sources)
}

/// Display label for a source path (its file name, or the whole path if it has
/// none) — used in progress lines and per-file build-log tags.
fn display_name_of(source: &Path) -> String {
    source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| source.to_string_lossy().into_owned())
}

/// Build the include resolver for one source: overlay dirs first, then the
/// manifest include dirs, then the source's own directory (the `DefaultResolver`
/// fallback). Overlay dirs shadow the stock headers — the slice harness's
/// `-m64` `with_overlay` prepend, now a first-class manifest feature. Shared by
/// the serial and parallel compile paths.
fn build_resolver(manifest: &ProjectManifest, source: &Path) -> Box<dyn IncludeResolver> {
    let base_dir = source
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.manifest_dir.clone());
    let fallback = DefaultResolver { base_dir };
    let search_dirs: Vec<PathBuf> = manifest
        .overlay_dirs
        .iter()
        .chain(manifest.include_dirs.iter())
        .cloned()
        .collect();
    if search_dirs.is_empty() {
        Box::new(fallback)
    } else {
        Box::new(SearchPathResolver {
            dirs: search_dirs,
            fallback,
        })
    }
}

/// One compiled translation unit, ready for the link step.
struct TuOutput {
    object: coff::Object,
    display_name: String,
    file_lines: u64,
    /// Captured `note:` lines for this TU (spilled to the build log in source
    /// order by the caller).
    note_lines: Vec<String>,
    /// Deferred/pruned counts for the one-line build summary.
    tally: crate::diag::NoteTally,
}

/// Compile one source to an object and write its `.obj` to `object_dir`,
/// capturing this TU's diagnostic notes into the returned [`TuOutput`]. The diag
/// sink is thread-local, so concurrent workers never cross-contaminate; the
/// capture guard restores the stderr default even on a panic. Used by the
/// parallel path (the serial path keeps its own live-progress loop).
fn compile_one_tu(
    manifest: &ProjectManifest,
    ix: usize,
    source: &Path,
    object_dir: &Path,
) -> Result<TuOutput, ProjectError> {
    let src = std::fs::read(source)
        .map_err(|e| ProjectError::new(format!("cannot read source '{}': {e}", source.display())))?;
    let display_name = display_name_of(source);
    let file_lines = count_lines(&src);
    let resolver = build_resolver(manifest, source);
    let file_name = source.to_string_lossy();

    let cap = crate::diag::Capture::begin();
    let compiled = compile_to_object_reported(
        &src,
        &file_name,
        resolver.as_ref(),
        manifest.target.target_kind(),
        &manifest.defines,
        &mut |_| {},
    );
    let note_lines = crate::diag::drain_lines();
    let tally = cap.finish();

    let object = compiled.map_err(|e| ProjectError::new(format!("{}:{e}", source.display())))?;
    let generated_name = generated_file_name(ix, &manifest.manifest_dir, source, "obj");
    let out_path = object_dir.join(generated_name);
    std::fs::write(&out_path, object.write()).map_err(|e| {
        ProjectError::new(format!(
            "cannot write generated object '{}': {e}",
            out_path.display()
        ))
    })?;
    Ok(TuOutput {
        object,
        display_name,
        file_lines,
        note_lines,
        tally,
    })
}

/// Serial compile path (jobs == 1): keeps the live per-phase progress line.
fn compile_sequential(
    manifest: &ProjectManifest,
    object_dir: &Path,
    log: &mut std::fs::File,
) -> Result<(Vec<coff::Object>, u64, crate::diag::NoteTally), ProjectError> {
    // RAII: restores the stderr default on every exit — success, early `?`, or a
    // panic — so the sink can never stick in capture mode for a later build.
    let capture = crate::diag::Capture::begin();
    let mut reporter = Reporter::new(manifest.sources.len());
    let mut generated_objects = Vec::with_capacity(manifest.sources.len());
    for (ix, source) in manifest.sources.iter().enumerate() {
        let src = std::fs::read(source).map_err(|e| {
            reporter.abort();
            ProjectError::new(format!("cannot read source '{}': {e}", source.display()))
        })?;
        let display_name = display_name_of(source);
        let file_lines = count_lines(&src);
        reporter.start_file(ix + 1, &display_name, file_lines);
        let resolver = build_resolver(manifest, source);
        let file_name = source.to_string_lossy();
        let compiled = compile_to_object_reported(
            &src,
            &file_name,
            resolver.as_ref(),
            manifest.target.target_kind(),
            &manifest.defines,
            &mut |phase| reporter.phase(phase),
        );
        let obj = match compiled {
            Ok(obj) => obj,
            Err(e) => {
                reporter.abort();
                return Err(ProjectError::new(format!("{}:{e}", source.display())));
            }
        };
        // Spill this file's captured notes to the log, tagged with the source.
        for line in crate::diag::drain_lines() {
            let _ = writeln!(log, "{display_name}: {line}");
        }
        let generated_name = generated_file_name(ix, &manifest.manifest_dir, source, "obj");
        let out_path = object_dir.join(generated_name);
        std::fs::write(&out_path, obj.write()).map_err(|e| {
            reporter.abort();
            ProjectError::new(format!(
                "cannot write generated object '{}': {e}",
                out_path.display()
            ))
        })?;
        generated_objects.push(obj);
    }
    reporter.finish();
    let lines_total = reporter.lines_total();
    let notes = capture.finish();
    Ok((generated_objects, lines_total, notes))
}

/// Parallel compile path: `jobs` worker threads pull TUs from a shared cursor.
/// Results are collected into source-indexed slots and drained in order, so the
/// link sees an identical source-order input (byte-identical output) and the
/// lowest-index error wins regardless of which worker failed first.
fn compile_parallel(
    manifest: &ProjectManifest,
    object_dir: &Path,
    log: &mut std::fs::File,
    jobs: usize,
) -> Result<(Vec<coff::Object>, u64, crate::diag::NoteTally), ProjectError> {
    let n = manifest.sources.len();
    let next = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<Result<TuOutput, ProjectError>>>> =
        Mutex::new((0..n).map(|_| None).collect());
    let print_lock = Mutex::new(());
    let painter = Painter::stderr();

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let ix = next.fetch_add(1, Ordering::Relaxed);
                    if ix >= n {
                        break;
                    }
                    let source = manifest.sources[ix].as_path();
                    let name = display_name_of(source);
                    let out = compile_one_tu(manifest, ix, source, object_dir);
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    {
                        let _g = print_lock.lock().expect("progress lock");
                        let tag = painter.dim(&format!("[{done}/{n}]"));
                        let label = if out.is_ok() {
                            painter.cyan(&name)
                        } else {
                            painter.red(&name)
                        };
                        eprintln!("{tag} {label}");
                    }
                    *slots.lock().expect("results lock").get_mut(ix).unwrap() = Some(out);
                }
            });
        }
    });

    let slots = slots.into_inner().expect("results lock");
    let mut generated_objects = Vec::with_capacity(n);
    let mut lines_total = 0u64;
    let mut notes = crate::diag::NoteTally::default();
    for slot in slots {
        // Drain in source order: the first (lowest-index) error wins.
        let tu = slot.expect("every TU slot was filled by a worker")?;
        lines_total += tu.file_lines;
        notes.deferred += tu.tally.deferred;
        notes.pruned += tu.tally.pruned;
        for line in &tu.note_lines {
            let _ = writeln!(log, "{}: {line}", tu.display_name);
        }
        generated_objects.push(tu.object);
    }
    Ok((generated_objects, lines_total, notes))
}

/// Count source lines as newline count plus a trailing partial line, so an
/// empty file is 0 and a file with no final newline still counts its last line.
fn count_lines(src: &[u8]) -> u64 {
    if src.is_empty() {
        return 0;
    }
    let newlines = src.iter().filter(|&&b| b == b'\n').count() as u64;
    if src.last() == Some(&b'\n') {
        newlines
    } else {
        newlines + 1
    }
}

fn parse_toml(text: &str, path: &Path) -> Result<ParsedToml, ProjectError> {
    let mut out = ParsedToml::default();
    let mut in_package = false;
    let mut seen_package = false;
    let mut seen_keys = BTreeMap::<String, usize>::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if line != "[package]" {
                return Err(ProjectError::at(
                    path,
                    line_no,
                    format!("unsupported table `{line}` (expected `[package]`)"),
                ));
            }
            if seen_package {
                return Err(ProjectError::at(
                    path,
                    line_no,
                    "duplicate `[package]` table",
                ));
            }
            seen_package = true;
            in_package = true;
            continue;
        }
        if !in_package {
            return Err(ProjectError::at(
                path,
                line_no,
                "key/value before any `[package]` table",
            ));
        }
        let kv = parse_key_value(&line, line_no, path)?;
        if let Some(first) = seen_keys.insert(kv.key.clone(), line_no) {
            return Err(ProjectError::at(
                path,
                line_no,
                format!(
                    "duplicate key `package.{}` (first defined at line {first})",
                    kv.key
                ),
            ));
        }
        out.package.push(kv);
    }
    if !seen_package {
        return Err(ProjectError::new(format!(
            "{}: missing required `[package]` table",
            path.display()
        )));
    }
    Ok(out)
}

fn parse_key_value(line: &str, line_no: usize, path: &Path) -> Result<RawKv, ProjectError> {
    let Some(eq) = line.find('=') else {
        return Err(ProjectError::at(path, line_no, "expected `key = value`"));
    };
    let key = line[..eq].trim();
    if !is_bare_key(key) {
        return Err(ProjectError::at(
            path,
            line_no,
            format!("invalid key `{key}`"),
        ));
    }
    let rhs = line[eq + 1..].trim();
    if rhs.is_empty() {
        return Err(ProjectError::at(path, line_no, "missing value after `=`"));
    }
    let value = match rhs.as_bytes()[0] {
        b'"' => RawValue::String(parse_string(rhs, line_no, path)?),
        b'[' => RawValue::StringArray(parse_string_array(rhs, line_no, path)?),
        _ => {
            return Err(ProjectError::at(
                path,
                line_no,
                format!("unrecognised value `{rhs}` (expected string or string array)"),
            ));
        }
    };
    Ok(RawKv {
        key: key.to_string(),
        value,
        line: line_no,
    })
}

fn finalize_manifest(raw: ParsedToml, path: &Path) -> Result<ProjectManifest, ProjectError> {
    const VALID_KEYS: &[&str] = &[
        "name",
        "sources",
        "output",
        "target",
        "subsystem",
        "overlay_dirs",
        "include_dirs",
        "defines",
        "resources",
        "resource_profile",
        "objects",
        "libs",
    ];
    for kv in &raw.package {
        if !VALID_KEYS.contains(&kv.key.as_str()) {
            let suggestion = nearest_key(&kv.key, VALID_KEYS)
                .map(|s| format!("; did you mean `{s}`?"))
                .unwrap_or_default();
            return Err(ProjectError::at(
                path,
                kv.line,
                format!("unknown key `package.{}`{suggestion}", kv.key),
            ));
        }
    }

    let manifest_path = path.to_path_buf();
    let manifest_dir = path_parent(path);

    let name = optional_string(&raw, "name", path)?;
    if matches!(name.as_deref(), Some("")) {
        return Err(ProjectError::new("package.name must not be empty"));
    }

    let source_values = required_array(&raw, "sources", path)?;
    if source_values.is_empty() {
        return Err(ProjectError::new("package.sources must not be empty"));
    }
    let sources = resolve_path_array(&manifest_dir, &source_values, "sources", path)?;
    for source in &sources {
        if !is_source_path(source) {
            return Err(ProjectError::new(format!(
                "source '{}' has unsupported extension",
                source.display()
            )));
        }
    }
    validate_unique_paths("sources", &sources)?;

    let output_value = optional_string(&raw, "output", path)?;
    if matches!(output_value.as_deref(), Some("")) {
        return Err(ProjectError::new("package.output must not be empty"));
    }
    let output_raw = output_value.unwrap_or_else(|| {
        let stem = name.clone().unwrap_or_else(|| {
            sources[0]
                .file_stem()
                .and_then(OsStr::to_str)
                .unwrap_or("a")
                .to_string()
        });
        format!("{stem}.exe")
    });
    let output = resolve_output_path(&manifest_dir, &output_raw)?;

    let target = match optional_string(&raw, "target", path)? {
        None => ProjectTarget::Win64,
        Some(value) if value == "win64" => ProjectTarget::Win64,
        Some(value) if value == "win32" => ProjectTarget::Win32,
        Some(value) if value.is_empty() => {
            return Err(ProjectError::new("package.target must not be empty"));
        }
        Some(value) => {
            return Err(ProjectError::new(format!(
                "unknown target '{value}' (expected win64 or win32)"
            )));
        }
    };

    let subsystem = match optional_string(&raw, "subsystem", path)? {
        None => None,
        Some(value) if value == "console" => Some(Subsystem::Console),
        Some(value) if value == "gui" || value == "windows" => Some(Subsystem::Gui),
        Some(value) if value.is_empty() => {
            return Err(ProjectError::new("package.subsystem must not be empty"));
        }
        Some(value) => {
            return Err(ProjectError::new(format!(
                "unknown subsystem '{value}' (expected console, gui, or windows)"
            )));
        }
    };

    let overlay_dirs = resolve_path_array(
        &manifest_dir,
        &optional_array(&raw, "overlay_dirs", path)?.unwrap_or_default(),
        "overlay_dirs",
        path,
    )?;
    validate_unique_paths("overlay_dirs", &overlay_dirs)?;

    let include_dirs = resolve_path_array(
        &manifest_dir,
        &optional_array(&raw, "include_dirs", path)?.unwrap_or_default(),
        "include_dirs",
        path,
    )?;
    validate_unique_paths("include_dirs", &include_dirs)?;

    let define_values = optional_array(&raw, "defines", path)?.unwrap_or_default();
    let defines = parse_defines(&define_values)?;

    let resources = resolve_resources(
        &manifest_dir,
        &optional_array(&raw, "resources", path)?.unwrap_or_default(),
        path,
    )?;
    validate_unique_resource_paths(&resources)?;

    let resource_profile = match optional_string(&raw, "resource_profile", path)? {
        None => ResourceProfile::Brc32,
        Some(value) if value == "brc32" => ResourceProfile::Brc32,
        Some(value) if value == "bc45" => ResourceProfile::Bc45,
        Some(value) if value.is_empty() => {
            return Err(ProjectError::new(
                "package.resource_profile must not be empty",
            ));
        }
        Some(value) => {
            return Err(ProjectError::new(format!(
                "unknown resource_profile '{value}' (expected brc32 or bc45)"
            )));
        }
    };

    let objects = resolve_path_array(
        &manifest_dir,
        &optional_array(&raw, "objects", path)?.unwrap_or_default(),
        "objects",
        path,
    )?;
    for object in &objects {
        if !ext_eq(object, "obj") {
            return Err(ProjectError::new(format!(
                "object '{}' must have .obj extension",
                object.display()
            )));
        }
    }
    validate_unique_paths("objects", &objects)?;

    let libs = resolve_path_array(
        &manifest_dir,
        &optional_array(&raw, "libs", path)?.unwrap_or_default(),
        "libs",
        path,
    )?;
    for lib in &libs {
        if !ext_eq(lib, "lib") {
            return Err(ProjectError::new(format!(
                "library '{}' must have .lib extension",
                lib.display()
            )));
        }
    }
    validate_unique_paths("libs", &libs)?;

    Ok(ProjectManifest {
        manifest_path,
        manifest_dir,
        name,
        sources,
        output,
        target,
        subsystem,
        overlay_dirs,
        include_dirs,
        defines,
        resources,
        resource_profile,
        objects,
        libs,
    })
}

fn optional_string(
    raw: &ParsedToml,
    key: &str,
    path: &Path,
) -> Result<Option<String>, ProjectError> {
    let Some(kv) = raw.package.iter().find(|kv| kv.key == key) else {
        return Ok(None);
    };
    match &kv.value {
        RawValue::String(value) => Ok(Some(value.clone())),
        RawValue::StringArray(_) => Err(ProjectError::at(
            path,
            kv.line,
            format!("package.{key} must be a string"),
        )),
    }
}

fn optional_array(
    raw: &ParsedToml,
    key: &str,
    path: &Path,
) -> Result<Option<Vec<String>>, ProjectError> {
    let Some(kv) = raw.package.iter().find(|kv| kv.key == key) else {
        return Ok(None);
    };
    match &kv.value {
        RawValue::StringArray(value) => Ok(Some(value.clone())),
        RawValue::String(_) => Err(ProjectError::at(
            path,
            kv.line,
            format!("package.{key} must be an array of strings"),
        )),
    }
}

fn required_array(raw: &ParsedToml, key: &str, path: &Path) -> Result<Vec<String>, ProjectError> {
    optional_array(raw, key, path)?.ok_or_else(|| {
        ProjectError::new(format!(
            "{}: missing required package.{key}",
            path.display()
        ))
    })
}

fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut in_string = false;
    let mut prev_backslash = false;
    for ch in line.chars() {
        match ch {
            '"' if !prev_backslash => {
                in_string = !in_string;
                out.push(ch);
            }
            '#' if !in_string => break,
            _ => out.push(ch),
        }
        if ch == '\\' && in_string {
            prev_backslash = !prev_backslash;
        } else {
            prev_backslash = false;
        }
    }
    out
}

fn parse_string(rhs: &str, line_no: usize, path: &Path) -> Result<String, ProjectError> {
    let bytes = rhs.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(ProjectError::at(path, line_no, "expected quoted string"));
    }
    let mut out = String::with_capacity(rhs.len());
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let trailing = rhs[i + 1..].trim();
                if !trailing.is_empty() {
                    return Err(ProjectError::at(
                        path,
                        line_no,
                        format!("unexpected trailing text after string: `{trailing}`"),
                    ));
                }
                return Ok(out);
            }
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return Err(ProjectError::at(
                        path,
                        line_no,
                        "unterminated escape in string",
                    ));
                }
                match bytes[i] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'0' => out.push('\0'),
                    other => {
                        return Err(ProjectError::at(
                            path,
                            line_no,
                            format!("unknown escape `\\{}` in string", other as char),
                        ));
                    }
                }
            }
            b'\n' | b'\r' => {
                return Err(ProjectError::at(path, line_no, "bare newline in string"));
            }
            b if b < 0x80 => out.push(b as char),
            _ => {
                let ch = rhs[i..].chars().next().unwrap_or('\u{FFFD}');
                out.push(ch);
                i += ch.len_utf8();
                continue;
            }
        }
        i += 1;
    }
    Err(ProjectError::at(path, line_no, "unterminated string"))
}

fn parse_string_array(rhs: &str, line_no: usize, path: &Path) -> Result<Vec<String>, ProjectError> {
    let bytes = rhs.as_bytes();
    if bytes.first() != Some(&b'[') {
        return Err(ProjectError::at(path, line_no, "expected array"));
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut prev_backslash = false;
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' if !prev_backslash => in_string = !in_string,
            b'[' if !in_string => depth += 1,
            b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            b'\\' if in_string => {
                prev_backslash = !prev_backslash;
                continue;
            }
            _ => {}
        }
        prev_backslash = false;
    }
    let Some(end) = end else {
        return Err(ProjectError::at(path, line_no, "unterminated array"));
    };
    let trailing = rhs[end + 1..].trim();
    if !trailing.is_empty() {
        return Err(ProjectError::at(
            path,
            line_no,
            format!("unexpected trailing text after array: `{trailing}`"),
        ));
    }
    let inner = rhs[1..end].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut elements = Vec::new();
    let mut buf = String::new();
    let mut in_string = false;
    let mut prev_backslash = false;
    for ch in inner.chars() {
        match ch {
            '"' if !prev_backslash => {
                in_string = !in_string;
                buf.push(ch);
            }
            ',' if !in_string => {
                let item = buf.trim();
                if item.is_empty() {
                    return Err(ProjectError::at(path, line_no, "empty array element"));
                }
                elements.push(parse_string(item, line_no, path)?);
                buf.clear();
            }
            _ => {
                if ch == '\\' && in_string {
                    prev_backslash = !prev_backslash;
                    buf.push(ch);
                    continue;
                }
                buf.push(ch);
            }
        }
        prev_backslash = false;
    }
    let item = buf.trim();
    if !item.is_empty() {
        elements.push(parse_string(item, line_no, path)?);
    } else if !elements.is_empty() {
        return Err(ProjectError::at(path, line_no, "trailing comma in array"));
    }
    Ok(elements)
}

fn is_bare_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_build_override(arg: &str) -> bool {
    matches!(
        arg,
        "-o" | "--out" | "--output" | "--target" | "--subsystem"
    ) || arg.starts_with("-D")
        || arg.starts_with("-I")
}

fn path_parent(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn resolve_path_array(
    root: &Path,
    raw: &[String],
    field: &str,
    _path: &Path,
) -> Result<Vec<PathBuf>, ProjectError> {
    let mut out = Vec::with_capacity(raw.len());
    for value in raw {
        if value.is_empty() {
            return Err(ProjectError::new(format!(
                "package.{field} must not contain empty paths"
            )));
        }
        out.push(resolve_input_path(root, value));
    }
    Ok(out)
}

fn resolve_resources(
    root: &Path,
    raw: &[String],
    path: &Path,
) -> Result<Vec<ResourceInput>, ProjectError> {
    let paths = resolve_path_array(root, raw, "resources", path)?;
    paths
        .into_iter()
        .map(|path| {
            if ext_eq(&path, "rc") {
                Ok(ResourceInput::Rc(path))
            } else if ext_eq(&path, "res") {
                Ok(ResourceInput::Res(path))
            } else {
                Err(ProjectError::new(format!(
                    "resource '{}' must have .rc or .res extension",
                    path.display()
                )))
            }
        })
        .collect()
}

fn resolve_input_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        lexical_normalize(&path)
    } else {
        lexical_normalize(&root.join(path))
    }
}

fn resolve_output_path(root: &Path, value: &str) -> Result<PathBuf, ProjectError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Err(ProjectError::new(
            "package.output must be relative in mdbcc.toml v1; absolute output paths are rejected",
        ));
    }
    if relative_path_escapes(&path) {
        return Err(ProjectError::new(
            "package.output must stay under the manifest directory",
        ));
    }
    Ok(lexical_normalize(&root.join(path)))
}

fn relative_path_escapes(path: &Path) -> bool {
    let mut depth = 0usize;
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                if depth == 0 {
                    return true;
                }
                depth -= 1;
            }
            Component::Prefix(_) | Component::RootDir => return true,
        }
    }
    false
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(comp.as_os_str());
            }
        }
    }
    out
}

fn parse_defines(raw: &[String]) -> Result<Vec<(String, String)>, ProjectError> {
    let mut out = Vec::with_capacity(raw.len());
    for value in raw {
        if value.is_empty() {
            return Err(ProjectError::new(
                "package.defines must not contain empty strings",
            ));
        }
        if let Some((name, body)) = value.split_once('=') {
            out.push((name.to_string(), body.to_string()));
        } else {
            out.push((value.clone(), "1".to_string()));
        }
    }
    Ok(out)
}

fn defines_map(defines: &[(String, String)]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, value) in defines {
        out.insert(name.clone(), value.clone());
    }
    out
}

fn is_source_path(path: &Path) -> bool {
    let rendered = path.to_string_lossy();
    rendered.ends_with(".C")
        || ["c", "cpp", "cc", "cxx"]
            .iter()
            .any(|ext| ext_eq(path, ext))
}

fn ext_eq(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}

fn validate_unique_paths(field: &str, paths: &[PathBuf]) -> Result<(), ProjectError> {
    let mut seen = BTreeSet::new();
    for path in paths {
        let key = path_key(path);
        if !seen.insert(key) {
            return Err(ProjectError::new(format!(
                "package.{field} contains duplicate path '{}'",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_unique_resource_paths(resources: &[ResourceInput]) -> Result<(), ProjectError> {
    let paths: Vec<PathBuf> = resources
        .iter()
        .map(|res| res.path().to_path_buf())
        .collect();
    validate_unique_paths("resources", &paths)
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn generated_file_name(index: usize, root: &Path, path: &Path, ext: &str) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let key = path_key(rel);
    let hash = fnv1a32(key.as_bytes());
    let mut stem = String::new();
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            stem.push(ch);
        } else if !stem.ends_with('_') {
            stem.push('_');
        }
    }
    let stem = stem.trim_matches('_');
    let stem = if stem.is_empty() { "input" } else { stem };
    format!("{index:04}-{stem}-{hash:08x}.{ext}")
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn nearest_key<'a>(key: &str, candidates: &'a [&str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|candidate| (*candidate, levenshtein(key, candidate)))
        .filter(|(_, dist)| *dist <= 2)
        .min_by_key(|(_, dist)| *dist)
        .map(|(candidate, _)| candidate)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let mut costs: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = i;
        costs[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let old = costs[j + 1];
            costs[j + 1] = if ca == cb {
                prev
            } else {
                1 + prev.min(costs[j]).min(costs[j + 1])
            };
            prev = old;
        }
    }
    costs[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_define_forms() {
        assert_eq!(
            parse_defines(&[
                "NAME".to_string(),
                "WINVER=0x0400".to_string(),
                "EMPTY=".to_string(),
            ])
            .unwrap(),
            vec![
                ("NAME".to_string(), "1".to_string()),
                ("WINVER".to_string(), "0x0400".to_string()),
                ("EMPTY".to_string(), "".to_string()),
            ]
        );
    }

    #[test]
    fn target_arch_labels_spell_out_bit_width() {
        // The banner relies on these spelling out "32 vs 64" explicitly; the
        // bare name (`win64`/`win32`) is the Display form used elsewhere.
        assert_eq!(ProjectTarget::Win64.arch_label(), "64-bit x86-64");
        assert_eq!(ProjectTarget::Win32.arch_label(), "32-bit x86");
        assert_eq!(ProjectTarget::Win64.to_string(), "win64");
        assert_eq!(ProjectTarget::Win32.to_string(), "win32");
    }

    #[test]
    fn generated_names_distinguish_same_stems() {
        let root = Path::new("p");
        let a = generated_file_name(0, root, Path::new("p/src/main.c"), "obj");
        let b = generated_file_name(1, root, Path::new("p/tests/main.c"), "obj");
        assert_ne!(a, b);
        assert!(a.ends_with(".obj"));
        assert!(b.ends_with(".obj"));
    }
}
