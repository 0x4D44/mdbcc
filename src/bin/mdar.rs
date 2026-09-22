//! `mdar` — minimal static-library (`.lib`) builder.
//!
//! Reads COFF `.obj` files, extracts each object's DEFINED external symbols
//! (PUBDEFs: `External` storage class, in a real section), and writes an
//! MS-format `!<arch>\n` archive that `mdlink` pulls from symbol-driven (only
//! the members needed to satisfy unresolved externals are linked). This is the
//! tool that builds the railc self-host library deliverables — `mdcw32.lib`
//! (RTL), `mdbids.lib` (BIDS), `mdowl.lib` (OWL) — from mdbcc-compiled source.
//!
//! Usage: `mdar -o <out.lib> <obj> [<obj> ...]`

use std::path::PathBuf;
use std::process::ExitCode;

use mdbcc::coff;
use mdbcc::link::archive::{build_archive_bytes, member_pubdefs_with_storage};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut out: Option<PathBuf> = None;
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "-h" | "--help" | "/?" => {
                println!("usage: mdar -o <out.lib> <obj> [<obj> ...]");
                return ExitCode::SUCCESS;
            }
            s => inputs.push(PathBuf::from(s)),
        }
        i += 1;
    }

    let Some(out) = out else {
        eprintln!("mdar: error: -o <out.lib> is required");
        return ExitCode::FAILURE;
    };
    if inputs.is_empty() {
        eprintln!("mdar: error: no input object files");
        return ExitCode::FAILURE;
    }

    let mut members: Vec<(String, Vec<u8>)> = Vec::with_capacity(inputs.len());
    let mut member_symbols: Vec<Vec<String>> = Vec::with_capacity(inputs.len());
    // Disambiguate duplicate basenames (e.g. NEW.o from two source dirs).
    let mut seen_names: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    // Global symbol-index dedup. First strong definition wins; weak-only
    // definitions still index so weak-only members can be pulled, but a later
    // strong definition replaces an earlier weak one. This mirrors the linker
    // fold rule and prevents header inline wrappers from hiding out-of-line RTL
    // bodies such as IOSTREAM/ISTGLINE's getline(char*, int, char).
    let mut indexed_syms: std::collections::HashMap<String, IndexedSym> =
        std::collections::HashMap::new();

    for path in &inputs {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("mdar: error: cannot read '{}': {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let obj = match coff::Object::read(&bytes) {
            Ok(o) => o,
            Err(e) => {
                eprintln!(
                    "mdar: error: '{}' is not a COFF object: {e:?}",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        // PUBDEFs (DEFINED external/weak-external symbols), globally deduped
        // with strong-over-weak promotion. See [`member_pubdefs_with_storage`]
        // for why weak definitions must index at all.
        let member_ix = members.len();
        let mut syms: Vec<String> = Vec::new();
        for pubdef in member_pubdefs_with_storage(&obj) {
            match indexed_syms.get_mut(&pubdef.name) {
                None => {
                    indexed_syms.insert(
                        pubdef.name.clone(),
                        IndexedSym {
                            member_ix,
                            storage: pubdef.storage,
                        },
                    );
                    syms.push(pubdef.name);
                }
                Some(prev)
                    if prev.storage == coff::StorageClass::WeakExternal
                        && pubdef.storage == coff::StorageClass::External =>
                {
                    if prev.member_ix == member_ix {
                        syms.retain(|n| n != &pubdef.name);
                    } else if let Some(prev_syms) = member_symbols.get_mut(prev.member_ix) {
                        prev_syms.retain(|n| n != &pubdef.name);
                    }
                    *prev = IndexedSym {
                        member_ix,
                        storage: pubdef.storage,
                    };
                    syms.push(pubdef.name);
                }
                Some(_) => {}
            }
        }
        let base = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "member.obj".into());
        let count = seen_names.entry(base.clone()).or_insert(0);
        let name = if *count == 0 {
            base.clone()
        } else {
            format!("{count}_{base}")
        };
        *count += 1;
        members.push((name, bytes));
        member_symbols.push(syms);
    }

    let lib = build_archive_bytes(&members, &member_symbols);
    if let Err(e) = std::fs::write(&out, &lib) {
        eprintln!("mdar: error: cannot write '{}': {e}", out.display());
        return ExitCode::FAILURE;
    }
    let nsyms: usize = member_symbols.iter().map(Vec::len).sum();
    println!(
        "mdar: wrote {} ({} members, {} symbols, {} bytes)",
        out.display(),
        members.len(),
        nsyms,
        lib.len()
    );
    ExitCode::SUCCESS
}

#[derive(Debug, Clone, Copy)]
struct IndexedSym {
    member_ix: usize,
    storage: coff::StorageClass,
}
