//! `mdlink` — the mdbcc linker driver (the analogue of Borland's
//! TLINK32.EXE and Microsoft's `link.exe` / `lld-link`).
//!
//! Takes one or more on-disk COFF `.obj` files plus (since S1c.7) any
//! number of `.lib` static-library archives and `.res` resource files, and
//! produces a PE32+ executable image. The library layer (`mdbcc::link::link`) is the
//! reusable engine; this binary is a thin CLI shell that handles arg
//! parsing, file I/O, and error reporting.
//!
//! Per HLD §10 Q-Cli (ratified): GNU-style long options are the primary
//! syntax, with MSVC-style aliases (`/SUBSYSTEM:`, `/ENTRY:`, `/OUT:`,
//! etc.) accepted for users coming from `cl /link` / `lld-link`. Borland-
//! style `-Tpe -Sc`-flavoured options are deferred to S8+.
//!
//! Examples:
//! ```text
//!   mdlink foo.obj bar.obj                        ; -> a.exe
//!   mdlink foo.obj bar.obj --out hello.exe        ; GNU style
//!   mdlink foo.obj /OUT:hello.exe /SUBSYSTEM:GUI  ; MSVC style
//!   mdlink foo.obj -o hello.exe                   ; short option
//! ```
//!
//! Unknown options are an error (no silent acceptance). The exit code is 0
//! on success and 1 on any failure, with the underlying error printed to
//! stderr.

use std::path::PathBuf;
use std::process::ExitCode;

use mdbcc::coff;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};

/// CLI argument parse result. `inputs` is the list of `.obj` paths in the
/// order they appeared on the command line (linker semantics depend on the
/// order — first definition wins, etc.).
struct CliArgs {
    inputs: Vec<PathBuf>,
    output: Option<PathBuf>,
    subsystem: Option<Subsystem>,
    entry: Option<String>,
    image_base: Option<u64>,
    stack_reserve: Option<u64>,
    stack_commit: Option<u64>,
    /// Target machine — selected by `-m32` / `-m64` / `/MACHINE:X86` /
    /// `/MACHINE:X64`. S2d defaults to x64 (legacy behaviour).
    machine: Option<coff::Machine>,
    /// W6 debugging aid: `--map PATH` — write a plain-text linker map
    /// (sorted `VA name` lines) alongside the PE. PE bytes are unchanged.
    map: Option<PathBuf>,
    /// Discovery aid: `--trace-archives PATH` — write a TSV listing archive
    /// member pulls and the unresolved symbol that caused each pull.
    archive_trace: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("mdlink");

    let parsed = match parse_args(prog, &args[1..]) {
        Ok(p) => p,
        Err(ParseOutcome::HelpRequested) => {
            print_usage(prog);
            return ExitCode::SUCCESS;
        }
        Err(ParseOutcome::Error(msg)) => {
            eprintln!("{prog}: error: {msg}");
            eprintln!("try '{prog} --help' for usage information");
            return ExitCode::FAILURE;
        }
    };

    if parsed.inputs.is_empty() {
        eprintln!("{prog}: error: no input files");
        eprintln!("try '{prog} --help' for usage information");
        return ExitCode::FAILURE;
    }

    // Read each input from disk and dispatch on extension: `.lib` becomes
    // Input::Archive (S1c.7), `.res` becomes Input::ResFile, and anything
    // else (typically `.obj`) becomes Input::CoffBytes. The library's link()
    // does the COFF decode, archive parsing, and resource merge — keeps the
    // CLI shell thin (one allocation per file; error reporting names the
    // offending file).
    let mut inputs: Vec<Input<'_>> = Vec::with_capacity(parsed.inputs.len());
    for path in &parsed.inputs {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{prog}: error: cannot read '{}': {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if extension.eq_ignore_ascii_case("lib") {
            inputs.push(Input::Archive {
                name: path.display().to_string(),
                bytes,
            });
        } else if extension.eq_ignore_ascii_case("res") {
            inputs.push(Input::ResFile {
                name: path.display().to_string(),
                bytes,
            });
        } else {
            inputs.push(Input::CoffBytes {
                name: path.display().to_string(),
                bytes,
            });
        }
    }

    // Build the LinkOpts. The defaults live in LinkOpts::default(); we
    // overlay any explicit CLI overrides on top.
    let mut opts = LinkOpts {
        // S1c.5 scope: console default; the user-explicit `--subsystem`
        // overrides this, and a future S1c.10 driver shim may add cross-
        // input auto-detection (per HLD §10 Q-Bcc). For now we keep the
        // behaviour predictable: explicit > default.
        subsystem: Subsystem::Console,
        ..LinkOpts::default()
    };
    if let Some(s) = parsed.subsystem {
        opts.subsystem = s;
    }
    if parsed.entry.is_some() {
        opts.entry = parsed.entry;
    }
    if let Some(b) = parsed.image_base {
        opts.image_base = b;
    }
    if let Some(r) = parsed.stack_reserve {
        opts.stack_reserve = r;
    }
    if let Some(c) = parsed.stack_commit {
        opts.stack_commit = c;
    }
    if parsed.map.is_some() {
        opts.map = parsed.map;
    }
    if parsed.archive_trace.is_some() {
        opts.archive_trace = parsed.archive_trace;
    }
    if let Some(m) = parsed.machine {
        opts.machine = m;
        // PE32 (i386) uses a different ImageBase by convention. Override
        // only if the user didn't explicitly request one — explicit
        // --image-base / /BASE wins over the implicit target default.
        if matches!(m, coff::Machine::I386) && parsed.image_base.is_none() {
            opts.image_base = 0x0040_0000;
        }
    }

    let exe = match link::link(&inputs, &opts) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{prog}: error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let out = parsed.output.unwrap_or_else(|| PathBuf::from("a.exe"));
    if let Err(e) = std::fs::write(&out, &exe) {
        eprintln!("{prog}: error: cannot write '{}': {e}", out.display());
        return ExitCode::FAILURE;
    }

    println!("{prog}: wrote {} ({} bytes)", out.display(), exe.len());
    ExitCode::SUCCESS
}

/// Outcome distinguished from the success case so the dispatcher knows
/// whether to exit 0 (`--help`) or 1 (real error).
enum ParseOutcome {
    HelpRequested,
    Error(String),
}

/// Parse the CLI tail after the program name. Returns a populated
/// [`CliArgs`] or a [`ParseOutcome`] describing why we stopped.
///
/// Both GNU long-form (`--out FOO`, `--out=FOO`) and MSVC alias forms
/// (`/OUT:FOO`) are accepted; MSVC aliases use `:`-separated values per
/// link.exe convention. Anything else starting with `-` or `/` is an
/// unknown option (we don't silently treat unknown flags as paths — that
/// would let typos in flag names silently become bogus inputs).
fn parse_args(prog: &str, args: &[String]) -> Result<CliArgs, ParseOutcome> {
    let mut out = CliArgs {
        inputs: Vec::new(),
        output: None,
        subsystem: None,
        entry: None,
        image_base: None,
        stack_reserve: None,
        stack_commit: None,
        machine: None,
        map: None,
        archive_trace: None,
    };

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        // Help is the only flag that shortcuts the rest of parsing.
        if matches!(arg.as_str(), "-h" | "--help" | "/?" | "/help") {
            return Err(ParseOutcome::HelpRequested);
        }

        // GNU style: `--out PATH` / `--out=PATH`, or short `-o PATH`.
        if let Some(val) = take_gnu_value(arg, &mut it, "--out", "-o")? {
            out.output = Some(PathBuf::from(val));
            continue;
        }
        if let Some(val) = take_gnu_value(arg, &mut it, "--subsystem", "")? {
            out.subsystem = Some(parse_subsystem(&val)?);
            continue;
        }
        if let Some(val) = take_gnu_value(arg, &mut it, "--entry", "")? {
            out.entry = Some(val);
            continue;
        }
        if let Some(val) = take_gnu_value(arg, &mut it, "--image-base", "")? {
            out.image_base = Some(parse_hex_u64(&val, "--image-base")?);
            continue;
        }
        if let Some(val) = take_gnu_value(arg, &mut it, "--map", "")? {
            out.map = Some(PathBuf::from(val));
            continue;
        }
        if let Some(val) = take_gnu_value(arg, &mut it, "--trace-archives", "")? {
            out.archive_trace = Some(PathBuf::from(val));
            continue;
        }
        if let Some(val) = take_gnu_value(arg, &mut it, "--stack-reserve", "")? {
            let (reserve, commit) = parse_stack(&val, "--stack-reserve")?;
            out.stack_reserve = Some(reserve);
            if let Some(c) = commit {
                out.stack_commit = Some(c);
            }
            continue;
        }

        // MSVC style: `/OUT:PATH`, case-insensitive on the flag name.
        if let Some(val) = take_msvc_value(arg, "/OUT") {
            out.output = Some(PathBuf::from(val));
            continue;
        }
        if let Some(val) = take_msvc_value(arg, "/SUBSYSTEM") {
            out.subsystem = Some(parse_subsystem(val)?);
            continue;
        }
        if let Some(val) = take_msvc_value(arg, "/ENTRY") {
            out.entry = Some(val.to_string());
            continue;
        }
        if let Some(val) = take_msvc_value(arg, "/BASE") {
            out.image_base = Some(parse_hex_u64(val, "/BASE")?);
            continue;
        }
        if let Some(val) = take_msvc_value(arg, "/STACK") {
            let (reserve, commit) = parse_stack(val, "/STACK")?;
            out.stack_reserve = Some(reserve);
            if let Some(c) = commit {
                out.stack_commit = Some(c);
            }
            continue;
        }

        // Target machine selection: `-m32` / `-m64` GNU-style + GCC-compat,
        // `/MACHINE:X86` / `/MACHINE:X64` MSVC-style. Per HLD §S2 Q-Driver
        // ratification: single binary, target-flag-selected (no separate
        // mdlink32 binary). `-m64` is the default; omitting selects x64.
        if arg == "-m32" {
            out.machine = Some(coff::Machine::I386);
            continue;
        }
        if arg == "-m64" {
            out.machine = Some(coff::Machine::Amd64);
            continue;
        }
        if let Some(val) = take_msvc_value(arg, "/MACHINE") {
            out.machine = Some(parse_machine(val)?);
            continue;
        }

        // Anything else starting with `-` or `/` is an unknown option.
        if arg.starts_with('-') || arg.starts_with('/') {
            return Err(ParseOutcome::Error(format!(
                "unknown option '{arg}'; try '{prog} --help'"
            )));
        }

        // Positional argument — an input `.obj` file.
        out.inputs.push(PathBuf::from(arg));
    }

    Ok(out)
}

/// Helper for GNU-style options. Accepts `--flag VAL`, `--flag=VAL`, and
/// (when `short` is non-empty) `-x VAL`. Returns `Ok(Some(val))` when
/// `arg` is the requested flag and a value has been pulled (advancing the
/// iterator if necessary); `Ok(None)` when `arg` is unrelated to this
/// flag; `Err(...)` when the flag was matched but the value was missing.
fn take_gnu_value<'a>(
    arg: &str,
    it: &mut std::slice::Iter<'a, String>,
    long: &str,
    short: &str,
) -> Result<Option<String>, ParseOutcome> {
    // `--flag=value` form.
    if let Some(rest) = arg.strip_prefix(long).and_then(|s| s.strip_prefix('=')) {
        if rest.is_empty() {
            return Err(ParseOutcome::Error(format!(
                "option '{long}' requires a value"
            )));
        }
        return Ok(Some(rest.to_string()));
    }
    // `--flag value` form.
    if arg == long {
        return match it.next() {
            Some(v) => Ok(Some(v.clone())),
            None => Err(ParseOutcome::Error(format!(
                "option '{long}' requires a value"
            ))),
        };
    }
    // `-x value` form (only when the caller provided a short alias).
    if !short.is_empty() && arg == short {
        return match it.next() {
            Some(v) => Ok(Some(v.clone())),
            None => Err(ParseOutcome::Error(format!(
                "option '{short}' requires a value"
            ))),
        };
    }
    Ok(None)
}

/// Helper for MSVC-style options. The link.exe convention is
/// `/FLAG:value` with the flag name being case-insensitive. We return the
/// raw value slice (the caller parses it into its specific shape).
fn take_msvc_value<'a>(arg: &'a str, flag: &str) -> Option<&'a str> {
    // MSVC tokens always start with `/`; bail early if the arg doesn't.
    if !arg.starts_with('/') {
        return None;
    }
    let arg_upper = arg.to_ascii_uppercase();
    let needle = format!("{flag}:");
    if arg_upper.starts_with(&needle) {
        // Slice the original `arg` (preserving case in the value) at the
        // offset of the matched needle length (the prefix is ASCII so the
        // byte offset matches the character offset).
        Some(&arg[needle.len()..])
    } else {
        None
    }
}

/// `x86` / `i386` / `32` (PE32) vs `x64` / `amd64` / `64` (PE32+). Mirrors
/// link.exe `/MACHINE:X86|X64` plus a couple of GCC-style spellings.
/// Case-insensitive. Per HLD §S2 Q-Driver ratification.
fn parse_machine(s: &str) -> Result<coff::Machine, ParseOutcome> {
    match s.to_ascii_lowercase().as_str() {
        "x86" | "i386" | "32" => Ok(coff::Machine::I386),
        "x64" | "amd64" | "64" => Ok(coff::Machine::Amd64),
        other => Err(ParseOutcome::Error(format!(
            "unknown machine '{other}'; valid values: x86, x64 (or i386, amd64)"
        ))),
    }
}

/// `console` / `gui` (GNU), `CONSOLE` / `GUI` (MSVC). Case-insensitive on
/// both forms.
fn parse_subsystem(s: &str) -> Result<Subsystem, ParseOutcome> {
    match s.to_ascii_lowercase().as_str() {
        "console" => Ok(Subsystem::Console),
        "gui" | "windows" => Ok(Subsystem::Gui),
        other => Err(ParseOutcome::Error(format!(
            "unknown subsystem '{other}'; valid values: console, gui"
        ))),
    }
}

/// `0x140000000` or `140000000` — link.exe accepts both. We accept both
/// too. The value is the requested PE ImageBase.
fn parse_hex_u64(s: &str, flag: &str) -> Result<u64, ParseOutcome> {
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(trimmed, 16)
        .map_err(|e| ParseOutcome::Error(format!("bad value for '{flag}': '{s}' ({e})")))
}

/// `/STACK:reserve[,commit]` and `--stack-reserve <reserve>[,<commit>]`.
/// link.exe accepts decimal or hex (`0x...`); we mirror that. Returns the
/// reserve and an optional commit.
fn parse_stack(s: &str, flag: &str) -> Result<(u64, Option<u64>), ParseOutcome> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(ParseOutcome::Error(format!(
            "bad value for '{flag}': '{s}' (expected RESERVE or RESERVE,COMMIT)"
        )));
    }
    let reserve = parse_u64(parts[0], flag)?;
    let commit = if parts.len() == 2 {
        Some(parse_u64(parts[1], flag)?)
    } else {
        None
    };
    Ok((reserve, commit))
}

/// Decimal-or-hex parser used by `/STACK:`. Strips a `0x` prefix if
/// present.
fn parse_u64(s: &str, flag: &str) -> Result<u64, ParseOutcome> {
    let res = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16)
    } else {
        s.parse::<u64>()
    };
    res.map_err(|e| ParseOutcome::Error(format!("bad value for '{flag}': '{s}' ({e})")))
}

fn print_usage(prog: &str) {
    // Print to stdout (not stderr) so `mdlink --help | less` works the
    // way users expect. Match the layout style of `bcc` (short message,
    // grouped by purpose) so the two CLIs feel consistent.
    println!("usage: {prog} [options] <obj> [<obj> ...]");
    println!();
    println!("Link one or more COFF .obj files into a PE32+ executable.");
    println!();
    println!("Options (GNU style; MSVC aliases shown in parentheses):");
    println!("  --out <path> (-o <path>, /OUT:<path>)   output path (default a.exe)");
    println!("  --subsystem console|gui (/SUBSYSTEM:CONSOLE|GUI)   PE subsystem");
    println!("  --entry <symbol> (/ENTRY:<symbol>)      entry-point override");
    println!("  --image-base <hex> (/BASE:<hex>)        ImageBase (default 0x140000000)");
    println!("  --stack-reserve <bytes>[,<commit>] (/STACK:<r>[,<c>])");
    println!("                                          stack reserve / commit");
    println!("  --trace-archives <path>                 write archive-pull TSV trace");
    println!("  -m32 / -m64 (/MACHINE:X86|X64)          target machine (default x64)");
    println!("  -h, --help, /?                          this help");
}
