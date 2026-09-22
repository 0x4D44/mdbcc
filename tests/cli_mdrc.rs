//! CLI tests for `mdrc`, the resource compiler driver used by the RailC
//! self-host workflow.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::rc;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("wrk_probe");
        path.push(format!("cli_mdrc_{}_{}_{}", tag, std::process::id(), n));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mdrc_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mdrc"))
}

fn run_mdrc(work_dir: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let out = Command::new(mdrc_exe())
        .current_dir(work_dir)
        .args(args)
        .output()
        .expect("spawn mdrc");
    (out.status.code(), out.stdout, out.stderr)
}

#[test]
fn mdrc_default_profile_matches_library_write_res() {
    let dir = TempDir::new("default");
    let rc_path = dir.0.join("app.rc");
    let res_path = dir.0.join("app.res");
    let source =
        "100 MENU\nBEGIN\n  POPUP \"File\"\n  BEGIN\n    MENUITEM \"Exit\", 200\n  END\nEND\n";
    std::fs::write(&rc_path, source).expect("write rc");

    let (code, stdout, stderr) = run_mdrc(&dir.0, &["app.rc", "-o", "app.res"]);
    assert_eq!(
        code,
        Some(0),
        "mdrc failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );

    let unit = rc::compile_file(&rc_path, &Default::default()).expect("compile rc");
    assert_eq!(
        std::fs::read(res_path).expect("read res"),
        rc::write_res(&unit),
        "default mdrc profile must match rc::write_res"
    );
}

#[test]
fn mdrc_bc45_profile_matches_library_write_res_bc45() {
    let dir = TempDir::new("bc45");
    let rc_path = dir.0.join("railc.rc");
    let res_path = dir.0.join("railc.res");
    let source = "\
MAIN_MENU MENU\nBEGIN\n  MENUITEM \"Exit\", 200\nEND\n\
\nSTRINGTABLE\nBEGIN\n  1 \"hello\"\nEND\n";
    std::fs::write(&rc_path, source).expect("write rc");

    let (code, stdout, stderr) = run_mdrc(
        &dir.0,
        &["--profile", "bc45", "-fo", "railc.res", "railc.rc"],
    );
    assert_eq!(
        code,
        Some(0),
        "mdrc failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );

    let unit = rc::compile_file(&rc_path, &Default::default()).expect("compile rc");
    assert_eq!(
        std::fs::read(res_path).expect("read res"),
        rc::write_res_bc45(&unit),
        "bc45 mdrc profile must match rc::write_res_bc45"
    );
}
