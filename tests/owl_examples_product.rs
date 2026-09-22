#![cfg(windows)]

//! Product-path acceptance for small stock BC4.52 OWL examples.
//!
//! Run with:
//! `mdtimeout 900 -- cargo test --release --test owl_examples_product -- --ignored --nocapture --test-threads=1`
//!
//! Prerequisites:
//! - BC4.52 source tree (`$MDBCC_BC45_ROOT`, else `wrk_oracle/bc452/BC45`)
//! - Win64 dependency libraries from `cargo bc45-libs-win64`

use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use mdbcc::link::Subsystem;
use mdbcc::project::{self, ProjectTarget};

#[derive(Clone, Copy)]
struct OwlExample {
    tag: &'static str,
    project_name: &'static str,
    source_rel: &'static str,
    output_rel: &'static str,
    title: &'static str,
    expected: ExpectedOwlOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedOwlOutcome {
    Green,
    KnownGap {
        phase: OwlPhase,
        reason: &'static str,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OwlPhase {
    Preprocess,
    Parse,
    Codegen,
    Link,
    Launch,
    WindowSmoke,
    DialogSmoke,
    Close,
}

impl OwlPhase {
    fn label(self) -> &'static str {
        match self {
            OwlPhase::Preprocess => "preprocess",
            OwlPhase::Parse => "parse",
            OwlPhase::Codegen => "codegen",
            OwlPhase::Link => "link",
            OwlPhase::Launch => "launch",
            OwlPhase::WindowSmoke => "window-smoke",
            OwlPhase::DialogSmoke => "dialog-smoke",
            OwlPhase::Close => "close",
        }
    }
}

fn all_owl_phases() -> [OwlPhase; 8] {
    [
        OwlPhase::Preprocess,
        OwlPhase::Parse,
        OwlPhase::Codegen,
        OwlPhase::Link,
        OwlPhase::Launch,
        OwlPhase::WindowSmoke,
        OwlPhase::DialogSmoke,
        OwlPhase::Close,
    ]
}

const OWL_EXAMPLES: &[OwlExample] = &[
    OwlExample {
        tag: "button",
        project_name: "owl_button",
        source_rel: "EXAMPLES/OWL/OWLAPI/BUTTON/BUTTONX.CPP",
        output_rel: "build/owl_button.exe",
        title: "Button Tester",
        expected: ExpectedOwlOutcome::Green,
    },
    OwlExample {
        tag: "instance",
        project_name: "owl_instance",
        source_rel: "EXAMPLES/OWL/OWLAPI/INSTANCE/INSTANCE.CPP",
        output_rel: "build/owl_instance.exe",
        title: "An Instance",
        expected: ExpectedOwlOutcome::Green,
    },
    OwlExample {
        tag: "static",
        project_name: "owl_static",
        source_rel: "EXAMPLES/OWL/OWLAPI/STATIC/STATICX.CPP",
        output_rel: "build/owl_static.exe",
        title: "Static Control Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Close,
            reason: "intermittent 0xC0000374 heap corruption before/during close",
        },
    },
    OwlExample {
        tag: "hello",
        project_name: "owl_hello",
        source_rel: "EXAMPLES/OWL/OWLAPPS/HELLO/HELLOAPP.CPP",
        output_rel: "build/owl_hello.exe",
        title: "Hello World!",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Launch,
            reason: "builds but exits 0xC0000005 before a top-level window",
        },
    },
    OwlExample {
        tag: "groupbox",
        project_name: "owl_groupbox",
        source_rel: "EXAMPLES/OWL/OWLAPI/GROUPBOX/GROUPBXX.CPP",
        output_rel: "build/owl_groupbox.exe",
        title: "GroupBox Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Launch,
            reason: "builds but exits 0xE0000002 before the GroupBox window",
        },
    },
    OwlExample {
        tag: "edit",
        project_name: "owl_edit",
        source_rel: "EXAMPLES/OWL/OWLAPI/EDIT/EDITX.CPP",
        output_rel: "build/owl_edit.exe",
        title: "Edit Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Link,
            reason: "unresolved common-dialog/GDI helper symbols in product probe",
        },
    },
    OwlExample {
        tag: "gauge",
        project_name: "owl_gauge",
        source_rel: "EXAMPLES/OWL/OWLAPI/GAUGE/GAUGEX.CPP",
        output_rel: "build/owl_gauge.exe",
        title: "Gauge Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Link,
            reason: "unresolved OWL/GDI helper symbols in product probe",
        },
    },
    OwlExample {
        tag: "listbox",
        project_name: "owl_listbox",
        source_rel: "EXAMPLES/OWL/OWLAPI/LISTBOX/LISTBOXX.CPP",
        output_rel: "build/owl_listbox.exe",
        title: "ListBox Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Link,
            reason: "unresolved OWL/GDI helper symbols in product probe",
        },
    },
    OwlExample {
        tag: "combobox",
        project_name: "owl_combobox",
        source_rel: "EXAMPLES/OWL/OWLAPI/COMBOBOX/COMBOBXX.CPP",
        output_rel: "build/owl_combobox.exe",
        title: "ComboBox Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Link,
            reason: "unresolved OWL/GDI helper symbols in product probe",
        },
    },
    OwlExample {
        tag: "slider",
        project_name: "owl_slider",
        source_rel: "EXAMPLES/OWL/OWLAPI/SLIDER/SLIDERX.CPP",
        output_rel: "build/owl_slider.exe",
        title: "Slider Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Link,
            reason: "unresolved OWL/GDI helper symbols in product probe",
        },
    },
    OwlExample {
        tag: "popup",
        project_name: "owl_popup",
        source_rel: "EXAMPLES/OWL/OWLAPI/POPUP/POPUP.CPP",
        output_rel: "build/owl_popup.exe",
        title: "Popup Tester",
        expected: ExpectedOwlOutcome::KnownGap {
            phase: OwlPhase::Launch,
            reason: "builds but exits 0xC0000005 before a top-level window",
        },
    },
];

#[test]
#[ignore = "depends on local BC4.52 source tree, Win64 BC45 libs, and an interactive desktop"]
fn owl_instance_product_builds_and_launches_win64() {
    assert_green_example("instance");
}

#[test]
#[ignore = "depends on local BC4.52 source tree, Win64 BC45 libs, and an interactive desktop"]
fn owl_button_product_builds_and_launches_win64() {
    assert_green_example("button");
}

#[test]
fn owl_product_matrix_inventory_has_q2_shape() {
    assert!(
        OWL_EXAMPLES.len() >= 10,
        "Q2 requires at least 10 stock OWL entries"
    );
    assert!(
        OWL_EXAMPLES
            .iter()
            .any(|e| e.tag == "button" && matches!(e.expected, ExpectedOwlOutcome::Green)),
        "BUTTON must remain represented as a green baseline"
    );
    assert!(
        OWL_EXAMPLES
            .iter()
            .any(|e| e.tag == "instance" && matches!(e.expected, ExpectedOwlOutcome::Green)),
        "INSTANCE must remain represented as a green baseline"
    );

    let phases = all_owl_phases();
    assert_eq!(phases.len(), 8);
    println!(
        "phase vocabulary: {}",
        phases
            .iter()
            .map(|phase| phase.label())
            .collect::<Vec<_>>()
            .join(",")
    );

    println!("tag,expected_phase,source,repro");
    for example in OWL_EXAMPLES {
        let phase = match example.expected {
            ExpectedOwlOutcome::Green => "green",
            ExpectedOwlOutcome::KnownGap { phase, .. } => phase.label(),
        };
        println!(
            "{},{},{},{}",
            example.tag,
            phase,
            example.source_rel,
            repro_command(example.tag)
        );
    }
}

#[test]
#[ignore = "depends on local BC4.52 source tree, Win64 BC45 libs, and an interactive desktop"]
fn owl_stock_product_matrix_win64() {
    let mut saw_product_prereq = false;
    let mut green_failures = Vec::new();

    println!("\n=== stock BC4.52 OWL Win64 product matrix ===");
    println!("tag,expected,observed,detail,repro");
    for example in OWL_EXAMPLES {
        let outcome = run_example(*example);
        if !matches!(outcome, OwlOutcome::EnvSkip { .. }) {
            saw_product_prereq = true;
        }
        println!(
            "{},{},{},{},{}",
            example.tag,
            expected_label(*example),
            outcome.label(),
            outcome.detail().replace(',', ";"),
            repro_command(example.tag)
        );
        if matches!(example.expected, ExpectedOwlOutcome::Green) && !outcome.accepts_green() {
            green_failures.push(format!(
                "{} expected green but observed {} ({})",
                example.tag,
                outcome.label(),
                outcome.detail()
            ));
        }
    }

    if !saw_product_prereq {
        eprintln!(
            "[owl_examples_product] SKIP matrix: BC4.52 source/lib prerequisites absent; \
             this is environment state, not product success"
        );
        return;
    }

    assert!(
        green_failures.is_empty(),
        "green stock OWL examples regressed:\n{}",
        green_failures.join("\n")
    );
}

fn assert_green_example(tag: &str) {
    let example = *OWL_EXAMPLES
        .iter()
        .find(|example| example.tag == tag)
        .unwrap_or_else(|| panic!("unknown OWL example tag {tag}"));
    assert!(
        matches!(example.expected, ExpectedOwlOutcome::Green),
        "{tag} is not a green baseline"
    );
    let outcome = run_example(example);
    assert!(
        outcome.accepts_green(),
        "{} product path regressed: {} ({})",
        example.tag,
        outcome.label(),
        outcome.detail()
    );
}

fn run_example(example: OwlExample) -> OwlOutcome {
    let manifest = match write_manifest(example) {
        Ok(manifest) => manifest,
        Err(outcome) => return outcome,
    };
    let report = match project::build_from_manifest_path(&manifest) {
        Ok(report) => report,
        Err(e) => {
            let detail = e.to_string();
            return OwlOutcome::Gap {
                phase: classify_build_error(&detail),
                detail,
            };
        }
    };
    if report.target != ProjectTarget::Win64 {
        return OwlOutcome::Gap {
            phase: OwlPhase::Link,
            detail: format!("manifest built {:?}, expected Win64", report.target),
        };
    }
    if report.subsystem != Subsystem::Gui {
        return OwlOutcome::Gap {
            phase: OwlPhase::Link,
            detail: format!(
                "manifest built {:?}, expected GUI subsystem",
                report.subsystem
            ),
        };
    }
    if report.source_count != 1 || report.lib_count != 4 {
        return OwlOutcome::Gap {
            phase: OwlPhase::Link,
            detail: format!(
                "manifest report shape changed: sources={} libs={}",
                report.source_count, report.lib_count
            ),
        };
    }
    if !report.output.is_file() {
        return OwlOutcome::Gap {
            phase: OwlPhase::Link,
            detail: format!("build did not write {}", report.output.display()),
        };
    }
    println!(
        "[owl_examples_product] {} built {} ({} lines, notes deferred={} pruned={})",
        example.tag,
        report.output.display(),
        report.lines_total,
        report.notes_deferred,
        report.notes_pruned
    );

    if !interactive_desktop() {
        return OwlOutcome::BuildOnly {
            detail: "no interactive window station (headless / Session-0)".to_string(),
        };
    }
    smoke_window(example, &report.output)
}

fn write_manifest(example: OwlExample) -> Result<PathBuf, OwlOutcome> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `$MDBCC_BC45_ROOT` first, so the harness works from a task worktree
    // (which has no `wrk_oracle/`); falls back to the in-repo tree.
    let bc45 = mdbcc::overlay::resolve_bc45_root(&repo)
        .unwrap_or_else(|| repo.join("wrk_oracle").join("bc452").join("BC45"));
    let include = bc45.join("INCLUDE");
    let source = bc45.join(path_from_slash(example.source_rel));
    if !bc45.is_dir() || !include.is_dir() || !source.is_file() {
        eprintln!(
            "[owl_examples_product] SKIP {}: BC4.52 fixture missing; expected source {} and include dir {}",
            example.tag,
            source.display(),
            include.display()
        );
        return Err(OwlOutcome::EnvSkip {
            detail: format!(
                "BC4.52 fixture missing; expected source {} and include dir {}",
                source.display(),
                include.display()
            ),
        });
    }

    // The repository ships only mdbcc's diffs against the Borland headers, so
    // the `include64/` overlay is built here from `wrk_owl_win64/patches/` plus
    // the user's own BC4.52 tree.
    let overlay = materialize_owl_overlay(&repo, &bc45)?.join("include64");

    let lib_dir = repo.join("target").join("bc45-libs").join("win64");
    let libs = [
        lib_dir.join("mdowl.lib"),
        lib_dir.join("mdstreams.lib"),
        lib_dir.join("mdcw32.lib"),
        lib_dir.join("mdbids.lib"),
    ];
    for lib in &libs {
        if !lib.is_file() {
            return Err(OwlOutcome::EnvSkip {
                detail: format!(
                    "missing {}; run `cargo bc45-libs-win64` before the OWL product acceptance test",
                    lib.display()
                ),
            });
        }
    }

    let root = repo
        .join("wrk_probe")
        .join("owl_examples_product")
        .join(example.tag);
    std::fs::create_dir_all(&root)
        .unwrap_or_else(|e| panic!("create product probe dir {}: {e}", root.display()));
    let manifest = root.join("mdbcc.toml");
    let text = format!(
        "[package]\n\
         name = \"{}\"\n\
         sources = [\"{}\"]\n\
         output = \"{}\"\n\
         target = \"win64\"\n\
         subsystem = \"gui\"\n\
         overlay_dirs = [\"{}\"]\n\
         include_dirs = [\"{}\"]\n\
         libs = [\"{}\", \"{}\", \"{}\", \"{}\"]\n",
        example.project_name,
        toml_path(&source),
        example.output_rel,
        toml_path(&overlay),
        toml_path(&include),
        toml_path(&libs[0]),
        toml_path(&libs[1]),
        toml_path(&libs[2]),
        toml_path(&libs[3]),
    );
    std::fs::write(&manifest, text)
        .unwrap_or_else(|e| panic!("write manifest {}: {e}", manifest.display()));
    Ok(manifest)
}

/// Build the Win64 OWL overlay by applying `wrk_owl_win64/patches/` to the
/// user's BC4.52 tree, and return the generated directory.
///
/// Env-skips loudly (like every other missing prerequisite here) when that tree
/// is absent. The output dir is private to this test binary so a concurrent
/// `build_bc45_libs` cannot race it, and it is built once per process because
/// every example wants it.
fn materialize_owl_overlay(repo: &Path, bc45: &Path) -> Result<PathBuf, OwlOutcome> {
    static OVERLAY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    OVERLAY
        .get_or_init(|| {
            if !bc45.join("SOURCE").join("OWL").is_dir() {
                return Err(format!(
                    "BC4.52 source tree absent ({}); set $MDBCC_BC45_ROOT — the Win64 OWL \
                     include overlay is built from it, not committed",
                    bc45.display()
                ));
            }
            let out = repo.join("target").join("owl-overlay-win64-examples");
            mdbcc::overlay::materialize(repo, bc45, &out)
                .map_err(|e| format!("cannot build the Win64 OWL overlay: {e}"))
        })
        .clone()
        .map_err(|detail| {
            eprintln!("[owl_examples_product] SKIP: {detail}");
            OwlOutcome::EnvSkip { detail }
        })
}

fn path_from_slash(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn toml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

#[derive(Debug)]
enum OwlOutcome {
    EnvSkip { detail: String },
    BuildOnly { detail: String },
    Pass { detail: String },
    Gap { phase: OwlPhase, detail: String },
}

impl OwlOutcome {
    fn label(&self) -> &'static str {
        match self {
            OwlOutcome::EnvSkip { .. } => "env-skip",
            OwlOutcome::BuildOnly { .. } => "build-only",
            OwlOutcome::Pass { .. } => "pass",
            OwlOutcome::Gap { phase, .. } => phase.label(),
        }
    }

    fn detail(&self) -> &str {
        match self {
            OwlOutcome::EnvSkip { detail }
            | OwlOutcome::BuildOnly { detail }
            | OwlOutcome::Pass { detail }
            | OwlOutcome::Gap { detail, .. } => detail,
        }
    }

    fn accepts_green(&self) -> bool {
        matches!(self, OwlOutcome::Pass { .. } | OwlOutcome::BuildOnly { .. })
    }
}

fn classify_build_error(message: &str) -> OwlPhase {
    let m = message.to_ascii_lowercase();
    if m.contains("cannot open include") || m.contains("preprocess") || m.contains("#include") {
        OwlPhase::Preprocess
    } else if m.contains("parse")
        || m.contains("expected")
        || m.contains("unknown type")
        || m.contains("no matching overload")
        || m.contains("ambiguous")
    {
        OwlPhase::Parse
    } else if m.contains("link failed")
        || m.contains("unresolved")
        || m.contains("machine mismatch")
        || m.contains("duplicate symbol")
    {
        OwlPhase::Link
    } else {
        OwlPhase::Codegen
    }
}

fn expected_label(example: OwlExample) -> String {
    match example.expected {
        ExpectedOwlOutcome::Green => "green".to_string(),
        ExpectedOwlOutcome::KnownGap { phase, reason } => {
            format!("known-{}: {}", phase.label(), reason)
        }
    }
}

fn repro_command(tag: &str) -> String {
    format!(
        "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1 # tag={tag}"
    )
}

type Hwnd = *mut c_void;
type Handle = *mut c_void;
type Bool = c_int;

const UOI_FLAGS: c_int = 1;
const WSF_VISIBLE: u32 = 0x0001;
const WM_CLOSE: u32 = 0x0010;

#[repr(C)]
struct UserObjectFlags {
    inherit: Bool,
    reserved: u32,
    flags: u32,
}

#[link(name = "user32")]
unsafe extern "system" {
    fn EnumWindows(callback: unsafe extern "system" fn(Hwnd, isize) -> Bool, lparam: isize)
    -> Bool;
    fn GetWindowThreadProcessId(hwnd: Hwnd, process_id: *mut u32) -> u32;
    fn GetWindowTextA(hwnd: Hwnd, text: *mut c_char, max_count: c_int) -> c_int;
    fn PostMessageA(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> Bool;
    fn GetProcessWindowStation() -> Handle;
    fn GetUserObjectInformationW(
        h: Handle,
        index: c_int,
        info: *mut c_void,
        len: u32,
        needed: *mut u32,
    ) -> Bool;
}

fn interactive_desktop() -> bool {
    unsafe {
        let sta = GetProcessWindowStation();
        if sta.is_null() {
            return false;
        }
        let mut flags = UserObjectFlags {
            inherit: 0,
            reserved: 0,
            flags: 0,
        };
        let mut needed = 0;
        let ok = GetUserObjectInformationW(
            sta,
            UOI_FLAGS,
            &mut flags as *mut _ as *mut c_void,
            std::mem::size_of::<UserObjectFlags>() as u32,
            &mut needed,
        );
        ok != 0 && (flags.flags & WSF_VISIBLE) != 0
    }
}

fn smoke_window(example: OwlExample, exe: &Path) -> OwlOutcome {
    let mut child = match Command::new(exe).spawn() {
        Ok(child) => child,
        Err(e) => {
            return OwlOutcome::Gap {
                phase: OwlPhase::Launch,
                detail: format!("spawn {} {}: {e}", example.tag, exe.display()),
            };
        }
    };
    let child_pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut hwnd = std::ptr::null_mut();
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|e| panic!("poll {} child: {e}", example.tag))
        {
            return OwlOutcome::Gap {
                phase: OwlPhase::Launch,
                detail: format!(
                    "exited before window '{}' appeared: {}",
                    example.title,
                    status_label(status)
                ),
            };
        }
        if let Some(candidate) = find_window_by_pid(child_pid) {
            hwnd = candidate;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if hwnd.is_null() {
        let _ = child.kill();
        let _ = child.wait();
        return OwlOutcome::Gap {
            phase: OwlPhase::WindowSmoke,
            detail: format!("did not create window '{}' within 5 seconds", example.title),
        };
    }

    let actual_title = window_text(hwnd);
    if actual_title != example.title {
        let _ = child.kill();
        let _ = child.wait();
        return OwlOutcome::Gap {
            phase: OwlPhase::WindowSmoke,
            detail: format!(
                "created top-level window with title {actual_title:?}; expected {:?}",
                example.title
            ),
        };
    }
    println!(
        "[owl_examples_product] {} showed '{actual_title}'",
        example.tag
    );

    let posted = unsafe { PostMessageA(hwnd, WM_CLOSE, 0, 0) };
    if posted == 0 {
        let _ = child.kill();
        let _ = child.wait();
        return OwlOutcome::Gap {
            phase: OwlPhase::Close,
            detail: "WM_CLOSE cleanup failed after visible-state gate".to_string(),
        };
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|e| panic!("poll {} child after close: {e}", example.tag))
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return OwlOutcome::Gap {
                phase: OwlPhase::Close,
                detail: "process did not exit within 5 seconds after WM_CLOSE".to_string(),
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let code = status
        .code()
        .expect("Windows process should report an exit code");
    if code == 0 || code == -1 {
        println!(
            "[owl_examples_product] {} closed with exit {code}",
            example.tag
        );
        OwlOutcome::Pass {
            detail: format!("showed '{actual_title}' and closed with exit {code}"),
        }
    } else {
        OwlOutcome::Gap {
            phase: OwlPhase::Close,
            detail: format!("post-visible close exited with {code:#x}"),
        }
    }
}

struct PidSearch {
    target_pid: u32,
    found: Hwnd,
}

unsafe extern "system" fn enum_pick_by_pid(hwnd: Hwnd, lparam: isize) -> Bool {
    let ctx = unsafe { &mut *(lparam as *mut PidSearch) };
    let mut owner = 0u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut owner);
    }
    if owner == ctx.target_pid {
        ctx.found = hwnd;
        0
    } else {
        1
    }
}

fn find_window_by_pid(pid: u32) -> Option<Hwnd> {
    let mut ctx = PidSearch {
        target_pid: pid,
        found: std::ptr::null_mut(),
    };
    unsafe {
        EnumWindows(enum_pick_by_pid, &mut ctx as *mut _ as isize);
    }
    (!ctx.found.is_null()).then_some(ctx.found)
}

fn window_text(hwnd: Hwnd) -> String {
    let mut buf = [0 as c_char; 256];
    let n = unsafe { GetWindowTextA(hwnd, buf.as_mut_ptr(), buf.len() as c_int) };
    if n <= 0 {
        return String::new();
    }
    let bytes: Vec<u8> = buf[..n as usize].iter().map(|&ch| ch as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn status_label(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit {code:#x}"),
        None => "no exit code".to_string(),
    }
}
