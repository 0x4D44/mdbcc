//! `mdrc` — minimal Win32 resource compiler driver for mdbcc.
//!
//! The library implementation lives in `mdbcc::rc`; this binary is the
//! command-line seam needed by the RailC self-host workflow:
//!
//! ```text
//!   mdrc RESOURCE/RAILC.RC -o railc.res --profile bc45
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use mdbcc::rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Brc32,
    Bc45,
}

struct CliArgs {
    input: PathBuf,
    output: Option<PathBuf>,
    profile: Profile,
    defines: HashMap<String, String>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("mdrc");

    let parsed = match parse_args(&args[1..]) {
        Ok(Some(args)) => args,
        Ok(None) => {
            print_usage(prog);
            return ExitCode::SUCCESS;
        }
        Err(msg) => {
            eprintln!("{prog}: error: {msg}");
            eprintln!("try '{prog} --help' for usage information");
            return ExitCode::FAILURE;
        }
    };

    let unit = match rc::compile_file(&parsed.input, &parsed.defines) {
        Ok(unit) => unit,
        Err(e) => {
            eprintln!("{}:{e}", parsed.input.display());
            return ExitCode::FAILURE;
        }
    };

    let bytes = match parsed.profile {
        Profile::Brc32 => rc::write_res(&unit),
        Profile::Bc45 => rc::write_res_bc45(&unit),
    };
    let output = parsed
        .output
        .unwrap_or_else(|| parsed.input.with_extension("res"));
    if let Err(e) = std::fs::write(&output, &bytes) {
        eprintln!("{prog}: error: cannot write '{}': {e}", output.display());
        return ExitCode::FAILURE;
    }

    println!("{prog}: wrote {} ({} bytes)", output.display(), bytes.len());
    ExitCode::SUCCESS
}

fn parse_args(args: &[String]) -> Result<Option<CliArgs>, String> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut profile = Profile::Brc32;
    let mut defines = HashMap::new();

    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" | "/?" => return Ok(None),
            "-o" | "--out" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err(format!("{arg} requires an argument"));
                };
                output = Some(PathBuf::from(value));
            }
            "--profile" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err("--profile requires an argument".into());
                };
                profile = parse_profile(value)?;
            }
            "--bc45" => profile = Profile::Bc45,
            "-D" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err("-D requires an argument".into());
                };
                let (name, value) = split_define(value)?;
                defines.insert(name, value);
            }
            s if s.starts_with("-D") => {
                let (name, value) = split_define(&s[2..])?;
                defines.insert(name, value);
            }
            s if s.starts_with("-fo") && s.len() > 3 => {
                output = Some(PathBuf::from(&s[3..]));
            }
            "-fo" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err("-fo requires an argument".into());
                };
                output = Some(PathBuf::from(value));
            }
            s if s.starts_with('-') || s.starts_with('/') => {
                return Err(format!("unknown option '{s}'"));
            }
            s => {
                if input.is_some() {
                    return Err("mdrc accepts exactly one .rc input".into());
                }
                input = Some(PathBuf::from(s));
            }
        }
        i += 1;
    }

    let Some(input) = input else {
        return Err("no input file".into());
    };

    Ok(Some(CliArgs {
        input,
        output,
        profile,
        defines,
    }))
}

fn parse_profile(value: &str) -> Result<Profile, String> {
    if value.eq_ignore_ascii_case("brc32") || value.eq_ignore_ascii_case("brc540") {
        Ok(Profile::Brc32)
    } else if value.eq_ignore_ascii_case("bc45") || value.eq_ignore_ascii_case("railc") {
        Ok(Profile::Bc45)
    } else {
        Err(format!("unknown resource profile '{value}'"))
    }
}

fn split_define(value: &str) -> Result<(String, String), String> {
    if value.is_empty() {
        return Err("empty -D define".into());
    }
    if let Some(eq) = value.find('=') {
        Ok((value[..eq].to_string(), value[eq + 1..].to_string()))
    } else {
        Ok((value.to_string(), "1".to_string()))
    }
}

fn print_usage(prog: &str) {
    println!(
        "usage: {prog} [--profile brc32|bc45] [-DNAME[=VALUE] ...] [-o OUT.res] INPUT.rc\n\
         \n\
         Profiles:\n\
           brc32  default brc32 5.40-compatible ordering\n\
           bc45   RailC/Borland C++ 4.5-compatible ordering"
    );
}
