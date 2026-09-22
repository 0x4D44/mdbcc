//! S0.4 — BCC 4.52 toolchain (BCC32 + TLINK32 + BRC32) as a callable Rust
//! oracle. Wires `wrk_oracle/bc452/BC45/BIN/` into integration tests.
//!
//! Design notes (carry forward from `support/mod.rs`):
//! - Std-only; no new crate dependencies (consistent with mod.rs).
//!   Inline SHA-256 + temp-dir handling.
//! - Self-skips loudly if the CD is absent (mirrors O2/O3 `cl`/bcc32 5.5.1
//!   self-skip — see `discover_cl` / `bcc` in mod.rs).
//! - Content-addressable cache keyed by SHA-256 of (toolchain id, src bytes,
//!   canonical opts). Lives under `target/oracle-cache/bcc452/` (git-ignored
//!   via top-level `target/` rule). Per testing-charter §8.
//! - BCC32 emits artefacts in the CWD by default, so every invocation runs
//!   in a fresh per-pid+counter work dir (same `work_dir()` pattern used
//!   elsewhere in this support tree) and results are copied into the cache.
//! - `BCC32.CFG` on this CD has `-ID:\BC45\INCLUDE / -LD:\BC45\LIB` hard-
//!   coded — paths that do not exist on Arthur's box. We therefore pass
//!   `-I` and `-L` explicitly on every invocation, overriding the cfg.
//! - The CD's BIN dir must be on PATH so BCC32 can spawn TLINK32 itself
//!   for the convenience build path.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Handles to the BCC 4.52 toolchain on disk plus an identity hash that
/// the cache mixes into every key so different tool builds never collide.
#[derive(Clone)]
pub struct BccOracle {
    bin: PathBuf,
    include: PathBuf,
    lib: PathBuf,
    bcc32: PathBuf,
    tlink32: PathBuf,
    brc32: PathBuf,
    /// SHA-256 hex of `BCC32.EXE` + `TLINK32.EXE` concatenated. Pinned at
    /// discovery time so we hash once and pay the cost of detecting a CD
    /// swap on the cache key, not on every call.
    tool_id_hex: String,
}

static DISCOVERED: OnceLock<Option<BccOracle>> = OnceLock::new();

impl BccOracle {
    /// Look for `wrk_oracle/bc452/BC45/BIN/BCC32.EXE`. Result is cached so
    /// repeated `discover()` calls are O(1) after the first.
    pub fn discover() -> Option<Self> {
        DISCOVERED.get_or_init(Self::discover_uncached).clone()
    }

    fn discover_uncached() -> Option<Self> {
        // Use backslashes throughout — Borland command-line tools
        // (TLINK32 1.50 especially) treat `/` as an option prefix and
        // mis-parse paths with forward slashes (e.g. `/bc452` becomes
        // "option c452").  `Path::join` on Windows happily mixes
        // separators; we explicitly canonicalise to `\`.
        let root = win_path(&repo_root().join("wrk_oracle\\bc452\\BC45"));
        let bin = root.join("BIN");
        let include = root.join("INCLUDE");
        let lib = root.join("LIB");
        let bcc32 = bin.join("BCC32.EXE");
        let tlink32 = bin.join("TLINK32.EXE");
        let brc32 = bin.join("BRC32.EXE");
        if !bcc32.exists() || !tlink32.exists() {
            return None;
        }
        // `BRC32.EXE` is not strictly required to build console programs;
        // its absence does not gate the oracle. Tests that need it can
        // probe `oracle.brc32_path().exists()`.
        let mut id_input = Vec::new();
        for p in [&bcc32, &tlink32] {
            if let Ok(bytes) = fs::read(p) {
                id_input.extend_from_slice(&bytes);
            }
        }
        let tool_id_hex = sha256_hex(&id_input);
        Some(BccOracle {
            bin,
            include,
            lib,
            bcc32,
            tlink32,
            brc32,
            tool_id_hex,
        })
    }

    /// Convenience accessors.
    pub fn bin_dir(&self) -> &Path {
        &self.bin
    }
    pub fn include_dir(&self) -> &Path {
        &self.include
    }
    pub fn lib_dir(&self) -> &Path {
        &self.lib
    }
    pub fn bcc32_path(&self) -> &Path {
        &self.bcc32
    }
    pub fn tlink32_path(&self) -> &Path {
        &self.tlink32
    }
    pub fn brc32_path(&self) -> &Path {
        &self.brc32
    }
    pub fn tool_id_hex(&self) -> &str {
        &self.tool_id_hex
    }
}

// ---------------------------------------------------------------------------
// Opts + result types
// ---------------------------------------------------------------------------

/// Source language. Picks the on-disk extension we hand BCC32 — the compiler
/// infers C vs C++ from the extension (`.c` vs `.cpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    C,
    Cpp,
}

impl Lang {
    fn ext(self) -> &'static str {
        match self {
            Lang::C => "c",
            Lang::Cpp => "cpp",
        }
    }
}

/// Compile-only options (`bcc32 -c`).
///
/// Note: BCC32 4.52 has no "quiet" flag (the bcc32 5.5.1 `-q` was added
/// later). Every invocation prints the version banner + the input file's
/// name to stdout; callers that diff output must filter that line.
#[derive(Debug, Clone)]
pub struct CompileOpts {
    pub lang: Lang,
    /// Additional `-D<name>=<val>` macros.
    pub defines: Vec<(String, String)>,
    /// Extra flags appended verbatim, e.g. `-O2` or `-w-`. Order-stable.
    pub extra: Vec<String>,
}

impl Default for CompileOpts {
    fn default() -> Self {
        Self {
            lang: Lang::C,
            defines: Vec::new(),
            extra: Vec::new(),
        }
    }
}

/// Link-only options (explicit `tlink32` invocation).
#[derive(Debug, Clone)]
pub struct LinkOpts {
    /// `-Tpe` => PE32 image. Currently the only thing we emit.
    pub pe: bool,
    /// `-ap` => console application; `-aa` => GUI.
    pub console: bool,
    /// Map file (`<name>.map`). Captured into the cache when present.
    pub want_map: bool,
    /// Libraries to link (e.g. `cw32.lib`, `import32.lib`). Order-stable.
    pub libs: Vec<String>,
    /// Optional CRT startup object (e.g. `c0x32.obj` for console). When
    /// `None`, the caller is on the hook for providing startup themselves
    /// — typical use: `Some("c0x32.obj")`.
    pub startup: Option<String>,
    /// Extra flags appended verbatim.
    pub extra: Vec<String>,
}

impl Default for LinkOpts {
    fn default() -> Self {
        Self {
            pe: true,
            console: true,
            want_map: false,
            libs: vec!["cw32.lib".into(), "import32.lib".into()],
            startup: Some("c0x32.obj".into()),
            extra: Vec::new(),
        }
    }
}

/// Build = compile + link in one BCC32 invocation (it auto-drives TLINK32).
#[derive(Debug, Clone)]
pub struct BuildOpts {
    pub lang: Lang,
    pub defines: Vec<(String, String)>,
    pub extra: Vec<String>,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            lang: Lang::C,
            defines: Vec::new(),
            extra: Vec::new(),
        }
    }
}

/// Run-time invocation options.
#[derive(Debug, Clone, Default)]
pub struct RunOpts {
    /// Wall-clock timeout. Defaults to 10 s if you skip past `with_default`.
    pub timeout: Option<Duration>,
    /// Optional CWD override; defaults to the directory the exe lives in.
    pub cwd: Option<PathBuf>,
}

/// Captured stdout/stderr/exit shared by every result type.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub exit: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl ToolOutput {
    pub fn ok(&self) -> bool {
        self.exit == Some(0) && !self.timed_out
    }
}

/// Whether the result was served from the on-disk cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Hit,
    Miss,
}

#[derive(Debug, Clone)]
pub struct CompileResult {
    pub obj: Option<PathBuf>,
    pub output: ToolOutput,
    pub cache: CacheStatus,
}

#[derive(Debug, Clone)]
pub struct LinkResult {
    pub exe: Option<PathBuf>,
    pub map: Option<PathBuf>,
    pub output: ToolOutput,
    pub cache: CacheStatus,
}

#[derive(Debug, Clone)]
pub struct BuildResult {
    pub exe: Option<PathBuf>,
    pub obj: Option<PathBuf>,
    pub output: ToolOutput,
    pub cache: CacheStatus,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub output: ToolOutput,
}

// ---------------------------------------------------------------------------
// Public oracle API
// ---------------------------------------------------------------------------

impl BccOracle {
    /// Compile a single TU to `.obj` with `bcc32 -c`. Source is written to a
    /// per-invocation sandbox; the resulting `.obj` is copied into the cache
    /// and that copy is returned (lifetime = lifetime of `target/`).
    pub fn compile(&self, src: &str, opts: &CompileOpts) -> CompileResult {
        let key = self.cache_key("compile", src, &canonical_compile(opts));
        let cache_dir = self.cache_path(&key);
        let _ = fs::create_dir_all(&cache_dir);

        if let Some(r) = self.try_load_compile(&cache_dir) {
            return r;
        }

        let work = work_dir("bcc_compile");
        let src_path = work.join(format!("t.{}", opts.lang.ext()));
        let obj_path = work.join("t.obj");
        if fs::write(&src_path, src.as_bytes()).is_err() {
            return CompileResult {
                obj: None,
                output: tool_output_failed("could not stage source"),
                cache: CacheStatus::Miss,
            };
        }

        let mut cmd = Command::new(&self.bcc32);
        cmd.current_dir(&work);
        self.set_child_env(&mut cmd);
        cmd.arg("-c");
        cmd.arg(format!("-I{}", self.include.display()));
        cmd.arg(format!("-L{}", self.lib.display()));
        for (k, v) in &opts.defines {
            if v.is_empty() {
                cmd.arg(format!("-D{k}"));
            } else {
                cmd.arg(format!("-D{k}={v}"));
            }
        }
        for x in &opts.extra {
            cmd.arg(x);
        }
        cmd.arg(format!("-o{}", obj_path.display()));
        cmd.arg(&src_path);

        let output = run_capture(&mut cmd, Duration::from_secs(60));
        let obj_in_cache = if obj_path.exists() {
            let dest = cache_dir.join("obj");
            let _ = fs::copy(&obj_path, &dest);
            Some(dest)
        } else {
            None
        };
        self.persist_output(&cache_dir, &output);
        CompileResult {
            obj: obj_in_cache,
            output,
            cache: CacheStatus::Miss,
        }
    }

    /// Link one or more `.obj` files into a `.exe` via TLINK32.
    pub fn link(&self, objs: &[&Path], opts: &LinkOpts) -> LinkResult {
        let obj_bytes = read_concat(objs);
        let key = self.cache_key("link", obj_bytes.as_str(), &canonical_link(opts));
        let cache_dir = self.cache_path(&key);
        let _ = fs::create_dir_all(&cache_dir);

        if let Some(r) = self.try_load_link(&cache_dir, opts.want_map) {
            return r;
        }

        let work = work_dir("bcc_link");
        // Stage every input .obj into the work dir under a stable name. We
        // also use *relative* names for the input objs and the output exe
        // + map: TLINK32 1.50 has a quirk where absolute Windows paths in
        // the output-exe / output-map positions can trigger a
        // C0000005 access violation deep in its arg parser. Relative
        // (CWD-resolved) paths sidestep it.
        let mut local_objs: Vec<String> = Vec::new();
        for (i, p) in objs.iter().enumerate() {
            let name = format!("u{i}.obj");
            let dest = work.join(&name);
            if fs::copy(p, &dest).is_err() {
                return LinkResult {
                    exe: None,
                    map: None,
                    output: tool_output_failed("could not stage obj"),
                    cache: CacheStatus::Miss,
                };
            }
            local_objs.push(name);
        }
        let exe_name = "out.exe";
        let map_name = "out.map";
        let exe = work.join(exe_name);
        let map = work.join(map_name);

        let mut cmd = Command::new(&self.tlink32);
        cmd.current_dir(&work);
        self.set_child_env(&mut cmd);
        if opts.pe {
            cmd.arg("-Tpe");
        }
        cmd.arg(if opts.console { "-ap" } else { "-aa" });
        cmd.arg("-c"); // case-sensitive
        cmd.arg(format!("-L{}", self.lib.display()));
        for x in &opts.extra {
            cmd.arg(x);
        }
        // TLINK32 command form (matches Borland's published response-file
        // syntax — TLINK32 1.50 parses argv with the same rules):
        //   tlink32 [flags] startup user1 user2,exe,map,lib1 lib2
        // The commas and section boundaries must be *inside* a single
        // argv token. Passing each `,` as its own token is what tripped
        // TLINK32's parser (C0000005 / "Invalid option"). To stay safe:
        //   - first N-1 inputs are separate args
        //   - the LAST input is concatenated with `,<exe>,<map>,<lib0>`
        //   - any remaining libs follow as separate args
        if let Some(s) = &opts.startup {
            cmd.arg(self.lib.join(s));
        }
        let (last, init) = match local_objs.split_last() {
            Some((last, init)) => (last.clone(), init.to_vec()),
            None => {
                return LinkResult {
                    exe: None,
                    map: None,
                    output: tool_output_failed("link called with no objs"),
                    cache: CacheStatus::Miss,
                };
            }
        };
        for o in &init {
            cmd.arg(o);
        }
        let first_lib = opts.libs.first().cloned().unwrap_or_default();
        cmd.arg(format!("{last},{exe_name},{map_name},{first_lib}"));
        for l in opts.libs.iter().skip(1) {
            cmd.arg(l);
        }
        // Debug aid: set MDBCC_BCC_ORACLE_DEBUG=1 to dump the argv. Keep
        // disabled by default so failing tests stay terse.
        if std::env::var_os("MDBCC_BCC_ORACLE_DEBUG").is_some() {
            eprintln!("[bcc_oracle] tlink32 argv:");
            eprintln!("  exe = {:?}", self.tlink32);
            eprintln!("  cwd = {:?}", work);
            for (i, a) in cmd.get_args().enumerate() {
                eprintln!("  arg[{i}] = {a:?}");
            }
        }

        let output = run_capture(&mut cmd, Duration::from_secs(60));
        let exe_in_cache = if exe.exists() {
            let dest = cache_dir.join("exe");
            let _ = fs::copy(&exe, &dest);
            Some(dest)
        } else {
            None
        };
        let map_in_cache = if opts.want_map && map.exists() {
            let dest = cache_dir.join("map");
            let _ = fs::copy(&map, &dest);
            Some(dest)
        } else {
            None
        };
        self.persist_output(&cache_dir, &output);
        LinkResult {
            exe: exe_in_cache,
            map: map_in_cache,
            output,
            cache: CacheStatus::Miss,
        }
    }

    /// Compile + link in one shot: `bcc32 <src>`. BCC32 calls TLINK32 itself
    /// when given a source file without `-c`. Requires TLINK32 on PATH.
    pub fn build(&self, src: &str, opts: &BuildOpts) -> BuildResult {
        let key = self.cache_key("build", src, &canonical_build(opts));
        let cache_dir = self.cache_path(&key);
        let _ = fs::create_dir_all(&cache_dir);

        if let Some(r) = self.try_load_build(&cache_dir) {
            return r;
        }

        let work = work_dir("bcc_build");
        let src_path = work.join(format!("t.{}", opts.lang.ext()));
        let obj_path = work.join("t.obj");
        let exe_path = work.join("t.exe");
        if fs::write(&src_path, src.as_bytes()).is_err() {
            return BuildResult {
                exe: None,
                obj: None,
                output: tool_output_failed("could not stage source"),
                cache: CacheStatus::Miss,
            };
        }

        let mut cmd = Command::new(&self.bcc32);
        cmd.current_dir(&work);
        self.set_child_env(&mut cmd);
        cmd.arg(format!("-I{}", self.include.display()));
        cmd.arg(format!("-L{}", self.lib.display()));
        for (k, v) in &opts.defines {
            if v.is_empty() {
                cmd.arg(format!("-D{k}"));
            } else {
                cmd.arg(format!("-D{k}={v}"));
            }
        }
        for x in &opts.extra {
            cmd.arg(x);
        }
        cmd.arg(format!("-e{}", exe_path.display()));
        cmd.arg(&src_path);

        let output = run_capture(&mut cmd, Duration::from_secs(120));
        let exe_in_cache = if exe_path.exists() {
            let dest = cache_dir.join("exe");
            let _ = fs::copy(&exe_path, &dest);
            Some(dest)
        } else {
            None
        };
        let obj_in_cache = if obj_path.exists() {
            let dest = cache_dir.join("obj");
            let _ = fs::copy(&obj_path, &dest);
            Some(dest)
        } else {
            None
        };
        self.persist_output(&cache_dir, &output);
        BuildResult {
            exe: exe_in_cache,
            obj: obj_in_cache,
            output,
            cache: CacheStatus::Miss,
        }
    }

    /// Run a built `.exe`, capturing stdout/stderr/exit. Not cached
    /// (running an exe is cheap; caching would freeze any process state).
    pub fn run(&self, exe: &Path, args: &[&str]) -> RunResult {
        self.run_with_opts(exe, args, &RunOpts::default())
    }

    pub fn run_with_opts(&self, exe: &Path, args: &[&str], opts: &RunOpts) -> RunResult {
        let timeout = opts.timeout.unwrap_or(Duration::from_secs(10));
        let mut cmd = Command::new(exe);
        if let Some(dir) = &opts.cwd {
            cmd.current_dir(dir);
        } else if let Some(parent) = exe.parent() {
            cmd.current_dir(parent);
        }
        for a in args {
            cmd.arg(a);
        }
        // Run with the BCC bin on PATH in case the binary loads BCC DLLs at
        // runtime (BC450RTL.DLL etc.). Console exes built against cw32.lib
        // are statically linked CRT, but staying consistent is cheap.
        self.set_child_env(&mut cmd);
        let output = run_capture(&mut cmd, timeout);
        RunResult { output }
    }

    // ----- env / paths ---------------------------------------------------

    fn set_child_env(&self, cmd: &mut Command) {
        // Don't `env_clear()` — Windows console tools want a baseline
        // environment (SystemRoot, TEMP, USERPROFILE, …) to run reliably.
        // We just *prepend* the BCC bin to whatever PATH the harness has.
        let cur_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = std::ffi::OsString::from(&self.bin);
        new_path.push(";");
        new_path.push(&cur_path);
        cmd.env("PATH", new_path);
    }

    // ----- cache ---------------------------------------------------------

    fn cache_root(&self) -> PathBuf {
        win_path(
            &repo_root()
                .join("target\\oracle-cache\\bcc452")
                .join(&self.tool_id_hex[..16]),
        )
    }

    fn cache_path(&self, key_hex: &str) -> PathBuf {
        // Two-level shard: short prefix dir then the full digest, matching
        // the May-26 plan's `<sha256-prefix>/<sha256>/...` layout.
        self.cache_root().join(&key_hex[..2]).join(key_hex)
    }

    fn cache_key(&self, kind: &str, src: &str, opts_canon: &str) -> String {
        let mut buf = Vec::with_capacity(64 + src.len() + opts_canon.len());
        buf.extend_from_slice(b"mdbcc/bcc452/v1\n");
        buf.extend_from_slice(b"kind=");
        buf.extend_from_slice(kind.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"tool=");
        buf.extend_from_slice(self.tool_id_hex.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"opts=");
        buf.extend_from_slice(opts_canon.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"src=");
        buf.extend_from_slice(src.as_bytes());
        sha256_hex(&buf)
    }

    fn persist_output(&self, dir: &Path, o: &ToolOutput) {
        let _ = fs::write(dir.join("stdout"), &o.stdout);
        let _ = fs::write(dir.join("stderr"), &o.stderr);
        let exit_str = match o.exit {
            Some(c) => format!("{c}"),
            None => "killed".to_string(),
        };
        let _ = fs::write(dir.join("exit"), exit_str.as_bytes());
        let _ = fs::write(
            dir.join("timed_out"),
            if o.timed_out { b"1" as &[u8] } else { b"0" },
        );
        // Sentinel — written *last* so partial writes can't be served as
        // a hit. `try_load_*` checks for this before trusting the entry.
        let _ = fs::write(dir.join("ok"), b"1");
    }

    fn try_load_output(&self, dir: &Path) -> Option<ToolOutput> {
        if !dir.join("ok").exists() {
            return None;
        }
        let stdout = fs::read(dir.join("stdout")).ok()?;
        let stderr = fs::read(dir.join("stderr")).ok()?;
        let exit_str = fs::read_to_string(dir.join("exit")).ok()?;
        let exit = if exit_str.trim() == "killed" {
            None
        } else {
            Some(exit_str.trim().parse::<i32>().ok()?)
        };
        let timed_out = fs::read(dir.join("timed_out")).ok().as_deref() == Some(b"1");
        Some(ToolOutput {
            exit,
            stdout,
            stderr,
            timed_out,
        })
    }

    fn try_load_compile(&self, dir: &Path) -> Option<CompileResult> {
        let output = self.try_load_output(dir)?;
        let obj_path = dir.join("obj");
        let obj = if obj_path.exists() {
            Some(obj_path)
        } else {
            None
        };
        Some(CompileResult {
            obj,
            output,
            cache: CacheStatus::Hit,
        })
    }

    fn try_load_link(&self, dir: &Path, want_map: bool) -> Option<LinkResult> {
        let output = self.try_load_output(dir)?;
        let exe_p = dir.join("exe");
        let exe = if exe_p.exists() { Some(exe_p) } else { None };
        let map_p = dir.join("map");
        let map = if want_map && map_p.exists() {
            Some(map_p)
        } else {
            None
        };
        Some(LinkResult {
            exe,
            map,
            output,
            cache: CacheStatus::Hit,
        })
    }

    fn try_load_build(&self, dir: &Path) -> Option<BuildResult> {
        let output = self.try_load_output(dir)?;
        let exe_p = dir.join("exe");
        let exe = if exe_p.exists() { Some(exe_p) } else { None };
        let obj_p = dir.join("obj");
        let obj = if obj_p.exists() { Some(obj_p) } else { None };
        Some(BuildResult {
            exe,
            obj,
            output,
            cache: CacheStatus::Hit,
        })
    }
}

// ---------------------------------------------------------------------------
// Canonical option strings — feed into the cache key. Must be order-stable.
// ---------------------------------------------------------------------------

fn canonical_compile(o: &CompileOpts) -> String {
    let mut s = String::new();
    let _ = write!(s, "lang={};", o.lang.ext());
    s.push_str("defs=[");
    for (k, v) in &o.defines {
        let _ = write!(s, "{k}={v},");
    }
    s.push_str("];extra=[");
    for x in &o.extra {
        s.push_str(x);
        s.push(',');
    }
    s.push(']');
    s
}

fn canonical_link(o: &LinkOpts) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "pe={};console={};want_map={};startup={};",
        o.pe as u8,
        o.console as u8,
        o.want_map as u8,
        o.startup.as_deref().unwrap_or("")
    );
    s.push_str("libs=[");
    for l in &o.libs {
        s.push_str(l);
        s.push(',');
    }
    s.push_str("];extra=[");
    for x in &o.extra {
        s.push_str(x);
        s.push(',');
    }
    s.push(']');
    s
}

fn canonical_build(o: &BuildOpts) -> String {
    let mut s = String::new();
    let _ = write!(s, "lang={};", o.lang.ext());
    s.push_str("defs=[");
    for (k, v) in &o.defines {
        let _ = write!(s, "{k}={v},");
    }
    s.push_str("];extra=[");
    for x in &o.extra {
        s.push_str(x);
        s.push(',');
    }
    s.push(']');
    s
}

fn read_concat(paths: &[&Path]) -> String {
    // For link cache keying we want a stable string capturing every input
    // .obj. Hash each file individually then concatenate the digests so we
    // don't carry many megabytes through the cache-key buffer.
    let mut s = String::new();
    for p in paths {
        let bytes = fs::read(p).unwrap_or_default();
        s.push_str(&sha256_hex(&bytes));
        s.push('|');
    }
    s
}

// ---------------------------------------------------------------------------
// Process running + capture (small reimpl — bcc_oracle stays self-contained)
// ---------------------------------------------------------------------------

fn run_capture(cmd: &mut Command, timeout: Duration) -> ToolOutput {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ToolOutput {
                exit: None,
                stdout: Vec::new(),
                stderr: format!("spawn failed: {e}").into_bytes(),
                timed_out: false,
            };
        }
    };
    let mut so = child.stdout.take().expect("piped stdout");
    let mut se = child.stderr.take().expect("piped stderr");
    let h_out = std::thread::spawn(move || read_all_capped(&mut so, 2 << 20));
    let h_err = std::thread::spawn(move || read_all_capped(&mut se, 256 << 10));

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => break None,
        }
    };
    let stdout = h_out.join().unwrap_or_default();
    let stderr = h_err.join().unwrap_or_default();
    let exit = status.and_then(|s| s.code());
    ToolOutput {
        exit,
        stdout,
        stderr,
        timed_out,
    }
}

fn read_all_capped<R: std::io::Read>(r: &mut R, cap: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match r.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&tmp[..take]);
                }
            }
            Err(_) => break,
        }
    }
    buf
}

fn tool_output_failed(reason: &str) -> ToolOutput {
    ToolOutput {
        exit: None,
        stdout: Vec::new(),
        stderr: reason.as_bytes().to_vec(),
        timed_out: false,
    }
}

// ---------------------------------------------------------------------------
// Per-invocation work dir + repo paths (mirrors mod.rs to keep this module
// independent of mod.rs visibility).
// ---------------------------------------------------------------------------

static DIR_N: AtomicU32 = AtomicU32::new(0);

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn work_dir(tag: &str) -> PathBuf {
    let n = DIR_N.fetch_add(1, Ordering::Relaxed);
    let d = win_path(&repo_root().join("target\\oracle").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        n
    )));
    let _ = fs::create_dir_all(&d);
    d
}

/// Canonicalise a `PathBuf` to use only backslashes — needed when handing
/// paths to Borland command-line tools (TLINK32, BCC32) because they
/// accept both `-X` and `/X` option prefixes, so a forward-slash inside a
/// path argument is mis-parsed as an option.
fn win_path(p: &Path) -> PathBuf {
    PathBuf::from(p.display().to_string().replace('/', "\\"))
}

// ---------------------------------------------------------------------------
// SHA-256 — std-only inline implementation (FIPS 180-4). Used for cache keys.
// ---------------------------------------------------------------------------

fn sha256_hex(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let mut i = 0;
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while i + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[i..i + 64]);
            self.compress(&block);
            i += 64;
        }
        if i < data.len() {
            let rem = data.len() - i;
            self.buf[..rem].copy_from_slice(&data[i..]);
            self.buf_len = rem;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        // append 0x80, then zero pad until length ≡ 56 (mod 64), then 8-byte
        // big-endian bit length.
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        let len_be = bit_len.to_be_bytes();
        self.update(&len_be);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the pure pieces (SHA-256, canonicalisation).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        // FIPS 180-2 appendix B examples.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
    }

    #[test]
    fn sha256_long_message_padding() {
        // 64 bytes — exactly one block, exercises the buffer flush path.
        let buf = vec![b'a'; 64];
        let expected = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
        assert_eq!(sha256_hex(&buf), expected);
    }

    #[test]
    fn canonical_strings_are_order_stable() {
        let a = CompileOpts {
            lang: Lang::Cpp,
            defines: vec![("A".into(), "1".into()), ("B".into(), "".into())],
            extra: vec!["-O2".into()],
        };
        let b = CompileOpts {
            lang: Lang::Cpp,
            defines: vec![("A".into(), "1".into()), ("B".into(), "".into())],
            extra: vec!["-O2".into()],
        };
        assert_eq!(canonical_compile(&a), canonical_compile(&b));
        // Re-ordering defines must produce a different canonical form (we
        // hash positional sequence, not set).
        let c = CompileOpts {
            lang: Lang::Cpp,
            defines: vec![("B".into(), "".into()), ("A".into(), "1".into())],
            extra: vec!["-O2".into()],
        };
        assert_ne!(canonical_compile(&a), canonical_compile(&c));
    }
}
