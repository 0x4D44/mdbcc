#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target_defines;
use mdbcc::link::archive;
use mdbcc::link::{self, Input, LinkError, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;
use mdbcc::project;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("wrk_probe");
        p.push(format!(
            "mdbcc_project_config_{}_{}_{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mdbcc_exe() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_BIN_EXE_mdbcc").expect("CARGO_BIN_EXE_mdbcc"))
}

fn run_mdbcc(work_dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(mdbcc_exe());
    cmd.current_dir(work_dir).args(args);
    let (code, out, err) = run_with_timeout(&mut cmd, Duration::from_secs(30));
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn command");
    let start = Instant::now();
    loop {
        if let Some(_status) = child.try_wait().expect("poll child") {
            let out = child.wait_with_output().expect("collect child output");
            return (out.status.code(), out.stdout, out.stderr);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let out = child.wait_with_output().expect("collect killed child");
            return (None, out.stdout, out.stderr);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn write_file(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, body).expect("write file");
}

fn pe_header(bytes: &[u8]) -> (u16, u16, u64) {
    assert!(bytes.len() > 0x100, "PE image too small");
    let pe_off = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&bytes[pe_off..pe_off + 4], b"PE\0\0");
    let machine = u16::from_le_bytes(bytes[pe_off + 4..pe_off + 6].try_into().unwrap());
    let opt = pe_off + 4 + 20;
    let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().unwrap());
    let image_base = if magic == 0x010b {
        u32::from_le_bytes(bytes[opt + 28..opt + 32].try_into().unwrap()) as u64
    } else {
        u64::from_le_bytes(bytes[opt + 24..opt + 32].try_into().unwrap())
    };
    (machine, magic, image_base)
}

#[test]
fn cli_documents_manifest_mode_and_rejects_non_manifest_invocations() {
    let dir = TempDir::new("cli");

    let (code, stdout, stderr) = run_mdbcc(dir.path(), &["--help"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(stdout.contains("mdbcc.toml"), "{stdout}");
    assert!(stdout.contains("--config"), "{stdout}");

    let (code, stdout, stderr) = run_mdbcc(dir.path(), &["--version"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(stdout.contains("mdbcc"), "{stdout}");

    let (code, _stdout, stderr) = run_mdbcc(dir.path(), &["hello.c"]);
    assert_ne!(code, Some(0));
    assert!(stderr.contains("positional"), "{stderr}");
    assert!(stderr.contains("bcc"), "{stderr}");

    let (code, _stdout, stderr) = run_mdbcc(dir.path(), &["-DWIN31"]);
    assert_ne!(code, Some(0));
    assert!(stderr.contains("unsupported build override"), "{stderr}");
}

#[test]
fn missing_config_and_parent_discovery_are_clear() {
    let dir = TempDir::new("discovery");
    let (code, _stdout, stderr) = run_mdbcc(dir.path(), &[]);
    assert_ne!(code, Some(0));
    assert!(stderr.contains("mdbcc.toml"), "{stderr}");

    write_file(
        dir.path(),
        "main.c",
        "int helper(void);\nint main(void) { return helper(); }\n",
    );
    write_file(dir.path(), "helper.c", "int helper(void) { return 17; }\n");
    write_file(
        dir.path(),
        "mdbcc.toml",
        "[package]\nsources = [\"main.c\", \"helper.c\"]\noutput = \"app.exe\"\n",
    );
    std::fs::create_dir_all(dir.path().join("child")).expect("create child");

    let (code, stdout, stderr) = run_mdbcc(&dir.path().join("child"), &[]);
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    assert!(dir.path().join("app.exe").is_file());
}

#[test]
fn config_path_controls_root_and_multisource_build_runs() {
    let dir = TempDir::new("config_root");
    let elsewhere = TempDir::new("elsewhere");
    write_file(dir.path(), "include/value.h", "#define FROM_HEADER 30\n");
    write_file(
        dir.path(),
        "src/main.c",
        "#include \"value.h\"\nint extra(void);\nint main(void) { return FROM_HEADER + extra() + FEATURE; }\n",
    );
    write_file(dir.path(), "src/extra.c", "int extra(void) { return 5; }\n");
    write_file(
        dir.path(),
        "mdbcc.toml",
        "[package]\n\
         sources = [\"src/main.c\", \"src/extra.c\"]\n\
         output = \"bin/app.exe\"\n\
         include_dirs = [\"include\"]\n\
         defines = [\"FEATURE=7\"]\n",
    );

    let manifest = dir.path().join("mdbcc.toml");
    let (code, stdout, stderr) =
        run_mdbcc(elsewhere.path(), &["--config", manifest.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    let exe = dir.path().join("bin/app.exe");
    assert!(exe.is_file(), "expected {}", exe.display());

    let run = Command::new(&exe).status().expect("run generated exe");
    assert_eq!(run.code(), Some(42));
    assert!(dir.path().join("target/mdbcc/objects").is_dir());
}

#[test]
fn overlay_dirs_shadow_include_dirs_for_same_named_header() {
    // `overlay_dirs` are searched BEFORE `include_dirs`, so a target-specific
    // header (here a stand-in for the Win64 `include64/` overlay) shadows a
    // stock header of the same name. Proven by the program returning the
    // OVERLAY's value (40), not the include dir's (1). This makes the slice
    // harness's `-m64` overlay prepend a first-class manifest feature.
    let dir = TempDir::new("overlay");
    write_file(dir.path(), "overlay/value.h", "#define VAL 40\n");
    write_file(dir.path(), "include/value.h", "#define VAL 1\n");
    write_file(
        dir.path(),
        "src/main.c",
        "#include \"value.h\"\nint main(void) { return VAL; }\n",
    );
    write_file(
        dir.path(),
        "mdbcc.toml",
        "[package]\n\
         sources = [\"src/main.c\"]\n\
         output = \"bin/app.exe\"\n\
         overlay_dirs = [\"overlay\"]\n\
         include_dirs = [\"include\"]\n",
    );

    let (code, stdout, stderr) = run_mdbcc(dir.path(), &[]);
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    let exe = dir.path().join("bin/app.exe");
    assert!(exe.is_file(), "expected {}", exe.display());
    let run = Command::new(&exe).status().expect("run generated exe");
    assert_eq!(
        run.code(),
        Some(40),
        "overlay header must shadow the same-named include_dirs header"
    );
}

#[test]
fn resources_compile_and_defines_apply_to_rc_files() {
    let dir = TempDir::new("resources");
    write_file(dir.path(), "main.c", "int main(void) { return 0; }\n");
    write_file(
        dir.path(),
        "app.rc",
        "#ifdef USE_ALT\nSTRINGTABLE\nBEGIN\n  1 \"alt\"\nEND\n#endif\n",
    );
    write_file(
        dir.path(),
        "mdbcc.toml",
        "[package]\n\
         sources = [\"main.c\"]\n\
         resources = [\"app.rc\"]\n\
         defines = [\"USE_ALT\"]\n\
         output = \"app.exe\"\n",
    );

    let (code, stdout, stderr) = run_mdbcc(dir.path(), &[]);
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    let exe = std::fs::read(dir.path().join("app.exe")).expect("read exe");
    assert!(
        exe.windows(b".rsrc".len()).any(|w| w == b".rsrc"),
        "linked executable should contain a .rsrc section"
    );
    assert!(dir.path().join("target/mdbcc/resources").is_dir());
}

#[test]
fn win32_target_builds_pe32_with_expected_headers() {
    let dir = TempDir::new("win32");
    write_file(
        dir.path(),
        "main.c",
        "int helper(void);\nint main(void) { return helper(); }\n",
    );
    write_file(dir.path(), "helper.c", "int helper(void) { return 9; }\n");
    write_file(
        dir.path(),
        "mdbcc.toml",
        "[package]\n\
         target = \"win32\"\n\
         sources = [\"main.c\", \"helper.c\"]\n\
         output = \"app32.exe\"\n",
    );

    let (code, stdout, stderr) = run_mdbcc(dir.path(), &[]);
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    let bytes = std::fs::read(dir.path().join("app32.exe")).expect("read exe");
    let (machine, magic, image_base) = pe_header(&bytes);
    assert_eq!(machine, 0x014c);
    assert_eq!(magic, 0x010b);
    assert_eq!(image_base, 0x0040_0000);

    match Command::new(dir.path().join("app32.exe")).status() {
        Ok(status) => assert_eq!(status.code(), Some(9)),
        Err(e) => eprintln!("[project_config] SKIP: host refused PE32 execution: {e}"),
    }
}

#[test]
fn omitted_subsystem_auto_detects_winmain() {
    let dir = TempDir::new("winmain");
    write_file(
        dir.path(),
        "main.c",
        "int WinMain(void* hInstance, void* hPrevInstance, char* lpCmdLine, int nCmdShow) { return 23; }\n",
    );
    write_file(
        dir.path(),
        "mdbcc.toml",
        "[package]\nsources = [\"main.c\"]\noutput = \"gui.exe\"\n",
    );

    let (code, stdout, stderr) = run_mdbcc(dir.path(), &[]);
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    let status = Command::new(dir.path().join("gui.exe"))
        .status()
        .expect("run WinMain exe");
    assert_eq!(status.code(), Some(23));
}

#[test]
fn parser_rejects_manifest_shape_and_schema_errors() {
    let cases = [
        ("missing package", "sources = [\"main.c\"]"),
        (
            "duplicate package",
            "[package]\nsources=[\"main.c\"]\n[package]\nname=\"x\"\n",
        ),
        ("unknown table", "[build]\nsources=[\"main.c\"]\n"),
        (
            "duplicate key",
            "[package]\nsources=[\"main.c\"]\nsources=[\"other.c\"]\n",
        ),
        (
            "unknown key",
            "[package]\nsources=[\"main.c\"]\nsorce=[\"typo.c\"]\n",
        ),
        ("wrong type", "[package]\nsources=\"main.c\"\n"),
        ("trailing comma", "[package]\nsources=[\"main.c\",]\n"),
        (
            "bad enum",
            "[package]\nsources=[\"main.c\"]\ntarget=\"dos\"\n",
        ),
        ("empty sources", "[package]\nsources=[]\n"),
        ("empty path", "[package]\nsources=[\"\"]\n"),
        (
            "bad source extension",
            "[package]\nsources=[\"main.txt\"]\n",
        ),
        (
            "duplicate normalized input",
            "[package]\nsources=[\"main.c\", \".\\\\main.c\"]\n",
        ),
    ];
    for (name, text) in cases {
        let err = project::parse_manifest_text(text, Path::new("case/mdbcc.toml"))
            .expect_err(name)
            .to_string();
        assert!(!err.is_empty(), "{name} should produce a non-empty error");
    }
}

#[test]
fn output_paths_are_contained_under_manifest_root() {
    let err = project::parse_manifest_text(
        "[package]\nsources=[\"main.c\"]\noutput=\"..\\\\escape.exe\"\n",
        Path::new("case/mdbcc.toml"),
    )
    .expect_err("relative output escape rejected")
    .to_string();
    assert!(err.contains("output"), "{err}");

    let abs = std::env::temp_dir().join("absolute.exe");
    let text = format!(
        "[package]\nsources=[\"main.c\"]\noutput=\"{}\"\n",
        abs.display().to_string().replace('\\', "\\\\")
    );
    let err = project::parse_manifest_text(&text, Path::new("case/mdbcc.toml"))
        .expect_err("absolute output rejected")
        .to_string();
    assert!(err.contains("absolute"), "{err}");

    let err = project::parse_manifest_text(
        "[package]\nsources=[\"main.c\"]\noutput=\"\\\\root.exe\"\n",
        Path::new("case/mdbcc.toml"),
    )
    .expect_err("root-relative output rejected")
    .to_string();
    assert!(err.contains("manifest directory"), "{err}");

    let err = project::parse_manifest_text(
        "[package]\nsources=[\"main.c\"]\noutput=\"C:drive.exe\"\n",
        Path::new("case/mdbcc.toml"),
    )
    .expect_err("drive-relative output rejected")
    .to_string();
    assert!(err.contains("manifest directory"), "{err}");
}

#[test]
fn link_rejects_machine_mismatched_objects_and_archive_members() {
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    let obj = compile_to_object_with_target_defines(
        b"int main(void) { return 0; }\n",
        "main.c",
        &resolver,
        mdbcc::codegen::target::TargetKind::Win64,
        &[],
    )
    .expect("compile x64 object");
    let opts = LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    };

    let err = link::link(&[Input::Object(&obj)], &opts).expect_err("object mismatch rejected");
    assert!(matches!(err, LinkError::MachineMismatch { .. }), "{err:?}");

    let caller = compile_to_object_with_target_defines(
        b"int foo(void); int main(void) { return foo(); }\n",
        "caller.c",
        &resolver,
        mdbcc::codegen::target::TargetKind::Win32,
        &[],
    )
    .expect("compile x86 caller");
    let def = compile_to_object_with_target_defines(
        b"int foo(void) { return 0; }\n",
        "foo.c",
        &resolver,
        mdbcc::codegen::target::TargetKind::Win64,
        &[],
    )
    .expect("compile x64 archive member");
    let archive_bytes = archive::build_archive_bytes(
        &[("foo.obj".to_string(), def.write())],
        &[vec!["foo".to_string(), "_foo".to_string()]],
    );
    let err = link::link(
        &[
            Input::Object(&caller),
            Input::Archive {
                name: "bad.lib".into(),
                bytes: archive_bytes,
            },
        ],
        &opts,
    )
    .expect_err("archive mismatch rejected");
    assert!(matches!(err, LinkError::MachineMismatch { .. }), "{err:?}");
}
