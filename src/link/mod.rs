//! `mdlink` linker library — root module.
//!
//! S1c.3 introduced the Object-consuming PE pipeline: [`link_single`] takes
//! a [`coff::Object`] and produces a PE32+ executable image. S1c.4 generalises
//! that path to multiple inputs via [`link`] (which accepts a slice of
//! [`Input`]), while keeping `link_single` as the single-Object shortcut used
//! by `compile_to_pe`. The legacy Module-consuming entry
//! [`pe_writer::write_pe_with_rsrc`] stays for one more tick (S1c.11 will
//! delete it).
//!
//! Subsequent S1c phases add `resolve`, `merge`, `reloc`, `idata`, `pdata`,
//! `rsrc`, `crt`, `omf`, `archive`, and `defparse` siblings per HLD §1.1.

pub mod archive;
pub mod crt;
pub mod defparse;
pub mod omf;
pub mod pe_writer;

use crate::coff;
use crate::rc::RcUnit;

pub use pe_writer::write_pe_with_rsrc;

/// Linker options — drives subsystem selection, image base, entry-point
/// override, stack / heap sizes, and post-S1c.3 features like CRT
/// synthesis (currently ignored — S1c.8 wires the stub).
#[derive(Debug, Clone)]
pub struct LinkOpts {
    /// IMAGE_FILE_MACHINE_* value for the output image.
    pub machine: coff::Machine,
    /// Subsystem: Console (3) or Gui (2).
    pub subsystem: Subsystem,
    /// Entry-point symbol. None ⇒ pick `main` for Console / `WinMain` for
    /// Gui (matches today's legacy default).
    pub entry: Option<String>,
    /// ImageBase. Default 0x1_4000_0000 matches the legacy writer.
    pub image_base: u64,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    /// Whether to synthesise the CRT startup stub. Ignored in S1c.3; the
    /// entry stub is emitted by the linker as before (S1c.8 wires the
    /// real CRT stub).
    pub synthesise_crt: bool,
    /// Treat warnings as errors. Currently unused — kept for forward
    /// compatibility with S1c.6+ (when the OMF reader gains warning
    /// emission).
    pub warnings_as_errors: bool,
    /// W5 (library-member duplicate folding): parallel to the object slice
    /// passed to `write_pe_from_objects` — `true` for an object PULLED FROM
    /// AN ARCHIVE, `false` (or absent) for an explicitly-listed object. A
    /// strong symbol duplicated when AT LEAST ONE side is archive-origin is
    /// FOLDED (first definition wins, library order — tlink/link.exe
    /// semantics: library members never conflict, only explicit objects do).
    /// Empty ⇒ every object treated as explicit (the historical behavior;
    /// all single-object and all-explicit links are byte-identical).
    pub archive_origin: Vec<bool>,
    /// W6 (debugging aid): when set, the PE writer ALSO writes a plain-text
    /// linker map — one `VA name` line per resolved external symbol, sorted
    /// by VA — to this path. Purely a side effect: the emitted PE bytes are
    /// identical with or without it.
    pub map: Option<std::path::PathBuf>,
    /// Debugging/discovery aid: when set, write a TSV trace of every archive
    /// member pulled during iterative resolution. Each row is
    /// `symbol<TAB>archive<TAB>member`, where `symbol` is the unresolved name
    /// that caused the pull. PE bytes are unchanged.
    pub archive_trace: Option<std::path::PathBuf>,
}

impl Default for LinkOpts {
    fn default() -> Self {
        Self {
            machine: coff::Machine::Amd64,
            subsystem: Subsystem::Console,
            entry: None,
            image_base: 0x1_4000_0000,
            stack_reserve: 0x100_000,
            stack_commit: 0x1000,
            heap_reserve: 0x100_000,
            heap_commit: 0x1000,
            synthesise_crt: false,
            warnings_as_errors: false,
            archive_origin: Vec::new(),
            map: None,
            archive_trace: None,
        }
    }
}

/// PE subsystem selector. The two values mdbcc currently emits.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Subsystem {
    /// IMAGE_SUBSYSTEM_WINDOWS_CUI (3).
    Console,
    /// IMAGE_SUBSYSTEM_WINDOWS_GUI (2).
    Gui,
}

/// Errors the linker can return. Mirrors HLD §1.2.
#[derive(Debug)]
pub enum LinkError {
    /// Reported in a single batch (per HLD §1.2 — "Reports ALL unresolved
    /// externals before failing"). Each entry carries the symbol name and
    /// an optional `(line, col)` source position (J-8b — the converter
    /// threads the first CallSite loc per undefined symbol so the message
    /// pinpoints the original `<line>:<col>: ` site, matching the legacy
    /// `pe::build_text` diagnostic format).
    UnresolvedExternals(Vec<(String, Option<(u32, u32)>)>),
    /// Duplicate strong definition of the same symbol across two inputs.
    /// Single-input (S1c.3) never raises this; reserved for S1c.4+.
    DuplicateSymbol { name: String },
    /// Bubbled-up COFF decoder error (e.g. truncated input).
    Coff(coff::CoffError),
    /// Bubbled-up OMF decoder error (S1c.6).
    Omf(omf::OmfError),
    /// Bubbled-up archive (`.lib`) reader error (S1c.7).
    Archive(archive::ArchiveError),
    /// A decoded object does not match the requested output machine.
    MachineMismatch {
        name: String,
        expected: coff::Machine,
        actual: coff::Machine,
    },
    /// Numeric / size overflow during PE layout.
    PeOverflow { what: &'static str },
    /// Catch-all for invariant violations or not-yet-implemented paths.
    Internal(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::UnresolvedExternals(items) => {
                // J-8b: when ANY entry has a known source loc, lead with
                // it so `<line>:<col>: ` appears at the start of the error
                // string — this is what `tests/error_locations.rs` greps
                // for via `first_line_col`. The legacy `pe::build_text`
                // pinpointed exactly one call site; we mirror that by
                // promoting the first loc-carrying entry to the prefix
                // and rendering the rest as a per-symbol bullet list.
                let first_with_loc = items
                    .iter()
                    .find_map(|(n, l)| l.map(|loc| (n.clone(), loc)));
                if let Some((name, (line, col))) = first_with_loc {
                    write!(f, "{line}:{col}: unresolved external function '{name}'")?;
                    let mut wrote_extra = false;
                    for (n, _) in items {
                        if n == &name {
                            continue;
                        }
                        if !wrote_extra {
                            write!(f, "\nadditional unresolved symbols:")?;
                            wrote_extra = true;
                        }
                        write!(f, "\n  {n}")?;
                    }
                    Ok(())
                } else {
                    write!(f, "unresolved external symbols:")?;
                    for (n, _) in items {
                        write!(f, "\n  {n}")?;
                    }
                    Ok(())
                }
            }
            LinkError::DuplicateSymbol { name } => {
                write!(f, "duplicate symbol '{name}'")
            }
            LinkError::Coff(e) => write!(f, "{e}"),
            LinkError::Omf(e) => write!(f, "{e}"),
            LinkError::Archive(e) => write!(f, "{e}"),
            LinkError::MachineMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "machine mismatch in '{name}': expected {expected:?}, got {actual:?}"
            ),
            LinkError::PeOverflow { what } => write!(f, "PE overflow: {what}"),
            LinkError::Internal(s) => write!(f, "internal linker error: {s}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<coff::CoffError> for LinkError {
    fn from(e: coff::CoffError) -> Self {
        LinkError::Coff(e)
    }
}

impl From<omf::OmfError> for LinkError {
    fn from(e: omf::OmfError) -> Self {
        LinkError::Omf(e)
    }
}

impl From<archive::ArchiveError> for LinkError {
    fn from(e: archive::ArchiveError) -> Self {
        LinkError::Archive(e)
    }
}

/// Pick the subsystem implied by the Object's defined entry points. Per
/// HLD §1.3: WinMain ⇒ Gui, else main ⇒ Console, else Console default.
pub fn auto_subsystem(obj: &coff::Object) -> Subsystem {
    use crate::coff::{SectionRef, StorageClass, SymName};
    // Helper: render the symbol name (Short or Long).
    let name_of = |sym: &coff::Symbol| -> String {
        match &sym.name {
            SymName::Short(arr) => {
                let end = arr.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&arr[..end]).into_owned()
            }
            SymName::Long(off) => obj
                .strtab
                .get_str(*off)
                .map(|s| s.to_string())
                .unwrap_or_default(),
        }
    };
    let mut has_main = false;
    let mut has_winmain = false;
    for sym in &obj.symbols {
        if sym.storage != StorageClass::External {
            continue;
        }
        if matches!(sym.section, SectionRef::Undefined) {
            continue;
        }
        let n = name_of(sym);
        if n == "main" || n == "_main" {
            has_main = true;
        } else if n == "WinMain" || n == "_WinMain@16" {
            has_winmain = true;
        }
    }
    if has_winmain {
        Subsystem::Gui
    } else {
        // Both `has_main` and the no-entry-defined case default to Console;
        // mdlink's entry-point selection treats the latter as "let the user
        // explicitly pass --entry" rather than failing here.
        let _ = has_main;
        Subsystem::Console
    }
}

fn validate_machine(
    name: impl Into<String>,
    obj: &coff::Object,
    expected: coff::Machine,
) -> Result<(), LinkError> {
    if obj.machine == expected {
        Ok(())
    } else {
        Err(LinkError::MachineMismatch {
            name: name.into(),
            expected,
            actual: obj.machine,
        })
    }
}

/// One input to the linker. Each variant carries the data plus a label
/// for diagnostic messages. Per HLD §1.2.
///
/// S1c.4 wired [`Input::Object`]; S1c.5 wired [`Input::CoffBytes`];
/// S1c.6 wired [`Input::OmfBytes`]; S1c.7 wired [`Input::Archive`]; resource
/// bytes wire through [`Input::ResFile`]. The remaining variant
/// ([`Input::DefFile`]) is reserved for S1c.9 and currently returns
/// [`LinkError::Internal`] with a "not yet supported" message pointing at
/// the responsible future tick.
pub enum Input<'a> {
    /// In-memory COFF Object (used by [`link_single`] / `compile_to_pe`).
    Object(&'a coff::Object),
    /// On-disk COFF `.obj` bytes (mdbcc-produced or other COFF producer).
    /// Decoded via [`coff::Object::read`] before linking.
    CoffBytes { name: String, bytes: Vec<u8> },
    /// On-disk OMF `.obj` bytes (bcc32-produced). Decoded via
    /// [`omf::read_to_coff`] before linking.
    OmfBytes { name: String, bytes: Vec<u8> },
    /// On-disk static-library archive (MS `!<arch>\n` format). Parsed by
    /// [`archive::Archive::read`]; members are pulled into the link only
    /// on demand to satisfy unresolved externals (HLD §4.3 iterative scan).
    Archive { name: String, bytes: Vec<u8> },
    /// On-disk .def file (parsed for EXPORTS / STACKSIZE / NAME). Reserved
    /// for S1c.9.
    DefFile { name: String, text: String },
    /// On-disk .res file (RC compiler output).
    ResFile { name: String, bytes: Vec<u8> },
}

/// Single-Object shortcut: link one in-memory [`coff::Object`] into a PE.
/// The entrypoint behind `compile_to_pe`.
///
/// Equivalent to [`link`] with a single-element `&[Input::Object(obj)]`
/// slice (R19 — verified byte-identical by
/// `tests/two_file_link.rs::single_object_through_link_matches_link_single`).
/// Kept as a public alias because `compile_to_pe`'s in-process path is
/// the common case and benefits from skipping the Input-slice plumbing.
pub fn link_single(obj: &coff::Object, opts: &LinkOpts) -> Result<Vec<u8>, LinkError> {
    validate_machine("<memory>", obj, opts.machine)?;
    pe_writer::write_pe_from_objects(&[obj], opts)
}

/// Multi-input link. Per HLD §1.2 — `link(&[Input::Object(foo), Input::Object(bar)], opts)`
/// merges N COFF Objects into a single PE32+ image.
///
/// S1c.4 introduced the multi-[`Input::Object`] path; S1c.5 activated the
/// on-disk [`Input::CoffBytes`] decode via [`coff::Object::read`]; S1c.6
/// activated [`Input::OmfBytes`] via [`omf::read_to_coff`]; S1c.7 activated
/// [`Input::Archive`] with iterative symbol-driven member pulling. The
/// remaining variant ([`Input::DefFile`]) returns [`LinkError::Internal`]
/// with a "deferred to S1c.<n>" message. For COFF
/// inputs the linker performs 7-pass processing (ingest → resolve → merge
/// → relocate → idata → pdata/xdata → headers) per HLD §2.
///
/// ## Archive scanning algorithm (HLD §4.3)
///
/// 1. Decode every non-archive input to a [`coff::Object`]; archives are
///    parsed structurally but no members are pulled yet.
/// 2. Compute the set of unresolved externals across the current object
///    list (every UNDEFINED EXTERNAL whose name is NOT a Win32 import and
///    NOT defined by any current object).
/// 3. For each unresolved name, scan the archives **in input order** for
///    the first that defines it. On a hit, decode the matching member
///    (COFF or OMF; sniffed via [`archive::Archive::detect_member_format`])
///    and append it to the object list. Mark the (archive, member) pair
///    as consumed so it is not pulled twice.
/// 4. Repeat from step 2 until a pass pulls no new members. Members
///    introduced by an archive pull may themselves reference further
///    unresolved externals; the loop converges because every iteration
///    either pulls one new member (bounded by total archive size) or
///    terminates.
/// 5. Surviving unresolved externals are left for
///    [`pe_writer::write_pe_from_objects`] to report — its
///    [`LinkError::UnresolvedExternals`] diagnostic carries the canonical
///    error shape (sorted names plus the first known source location).
pub fn link(inputs: &[Input<'_>], opts: &LinkOpts) -> Result<Vec<u8>, LinkError> {
    // Decode each non-archive input to an owned coff::Object. Archives are
    // parsed into [`archive::Archive`] but no members are extracted yet —
    // step 3 of the algorithm pulls them on demand.
    let mut decoded: Vec<coff::Object> = Vec::new();
    let mut archives: Vec<(String, archive::Archive)> = Vec::new();
    let mut res_files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut archive_trace_events: Vec<ArchiveTraceEvent> = Vec::new();
    // Tracks (archive_ix, member_ix) pairs already pulled so we never pull
    // the same member twice (and incidentally don't loop forever on a
    // symbol that's defined by an already-pulled member which itself still
    // declares the symbol as External).
    let mut consumed_members: std::collections::BTreeSet<(usize, usize)> =
        std::collections::BTreeSet::new();

    let mut slots: Vec<Slot> = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        match inp {
            Input::Object(obj) => {
                validate_machine(format!("input #{i}"), obj, opts.machine)?;
                slots.push(Slot::Borrowed(i));
            }
            Input::CoffBytes { name, bytes } => {
                let obj = coff::Object::read(bytes)?;
                validate_machine(name, &obj, opts.machine)?;
                let owned_ix = decoded.len();
                decoded.push(obj);
                slots.push(Slot::Owned(owned_ix));
            }
            Input::OmfBytes { name, bytes } => {
                let obj = omf::read_to_coff(bytes)?;
                validate_machine(name, &obj, opts.machine)?;
                let owned_ix = decoded.len();
                decoded.push(obj);
                slots.push(Slot::Owned(owned_ix));
            }
            Input::Archive { name, bytes } => {
                // Parse the archive structurally; members are pulled in the
                // archive-scan loop below based on unresolved symbols. An
                // archive in the inputs list contributes ZERO bytes to the
                // output unless one of its members satisfies an unresolved
                // external (matches link.exe / lld-link semantics).
                archives.push((name.clone(), archive::Archive::read(bytes)?));
            }
            Input::DefFile { name, .. } => {
                return Err(LinkError::Internal(format!(
                    ".def file '{name}' not yet supported (S1c.9 work — \
                     S1c.4 supports Object/CoffBytes only)"
                )));
            }
            Input::ResFile { name, bytes } => {
                res_files.push((name.clone(), bytes.clone()));
            }
        }
    }

    // Archive scan loop. Each iteration:
    //   - computes the set of unresolved externals across (decoded ∪ borrowed);
    //   - pulls in archive members that satisfy them;
    //   - re-runs until a pass pulls nothing new.
    //
    // The borrowed object slice is rebuilt at the top of each iteration so
    // newly-pulled `decoded` entries participate in the resolution scan.
    if !archives.is_empty() {
        loop {
            let objects = build_object_slice(inputs, slots.as_slice(), &decoded);
            let entry_root = archive_entry_root(opts);
            let unresolved =
                collect_unresolved_externals(&objects, std::iter::once(entry_root.as_str()));
            if unresolved.is_empty() {
                break;
            }
            let mut pulled_any = false;
            for name in &unresolved {
                for (ar_ix, (archive_name, ar)) in archives.iter().enumerate() {
                    if let Some(mem_ix) = ar.find_member_for_symbol(name) {
                        if consumed_members.contains(&(ar_ix, mem_ix)) {
                            continue;
                        }
                        let bytes = ar.member_bytes(mem_ix);
                        let obj = match ar.detect_member_format(mem_ix) {
                            archive::MemberFormat::CoffI386 | archive::MemberFormat::CoffAmd64 => {
                                coff::Object::read(bytes)?
                            }
                            archive::MemberFormat::Omf => omf::read_to_coff(bytes)?,
                            archive::MemberFormat::Unknown => {
                                return Err(LinkError::Internal(format!(
                                    "archive member '{}' (index {}) has unknown \
                                     format (neither COFF nor OMF — first byte \
                                     0x{:02x})",
                                    ar.member_name(mem_ix),
                                    mem_ix,
                                    bytes.first().copied().unwrap_or(0)
                                )));
                            }
                        };
                        validate_machine(
                            format!("{}({})", archive_name, ar.member_name(mem_ix)),
                            &obj,
                            opts.machine,
                        )?;
                        archive_trace_events.push(ArchiveTraceEvent {
                            symbol: name.clone(),
                            archive: archive_name.clone(),
                            member: ar.member_name(mem_ix).to_string(),
                        });
                        decoded.push(obj);
                        consumed_members.insert((ar_ix, mem_ix));
                        pulled_any = true;
                        // First archive wins for this symbol (HLD §4.3,
                        // matches link.exe / lld-link). Move on to the next
                        // unresolved name; further symbols may be satisfied
                        // by the same just-pulled member during the next
                        // pass.
                        break;
                    }
                }
            }
            if !pulled_any {
                // No archive can satisfy any remaining unresolved name.
                // Leave the survivors for write_pe_from_objects to report
                // via its canonical UnresolvedExternals diagnostic.
                break;
            }
        }
    }
    write_archive_trace(opts.archive_trace.as_deref(), &archive_trace_events)?;

    // S1c.8 — when synthesise_crt is enabled, build the CRT startup Object
    // and prepend it to the link set. Q-CRT ratification (HLD §10): the
    // stub's symbols use WeakExternal so S5+ real Borland RTL overrides.
    // The default for `synthesise_crt` is false today to preserve the 88
    // SipHash baselines; opt-in callers (tests, future driver-flag) set it
    // true. Flipping the default is S1c.11 close-out work.
    let synth_crt_obj = if opts.synthesise_crt {
        Some(crt::synthesise_startup_object(opts))
    } else {
        None
    };

    // Final pass: hand the merged object list to the PE writer. Archives
    // appear as ZERO-byte contributions if none of their members were
    // pulled — they're omitted from the slice entirely (we built `slots`
    // without archive entries).
    let mut objects = build_object_slice(inputs, slots.as_slice(), &decoded);
    // W5: archive-origin flags PARALLEL to `objects`, replicating
    // `build_object_slice`'s order — slot entries are explicit (false), the
    // appended unreferenced `decoded` entries are the archive pull-ins (true).
    let mut archive_origin: Vec<bool> = vec![false; slots.len()];
    let referenced: std::collections::BTreeSet<usize> = slots
        .iter()
        .filter_map(|s| match *s {
            Slot::Owned(i) => Some(i),
            _ => None,
        })
        .collect();
    for i in 0..decoded.len() {
        if !referenced.contains(&i) {
            archive_origin.push(true);
        }
    }
    if let Some(ref crt_obj) = synth_crt_obj {
        objects.push(crt_obj);
        archive_origin.push(false); // synthesized CRT is explicit
    }
    let opts = LinkOpts {
        archive_origin,
        ..opts.clone()
    };
    let pe = pe_writer::write_pe_from_objects(&objects, &opts)?;
    if res_files.is_empty() {
        Ok(pe)
    } else {
        let refs: Vec<(&str, &[u8])> = res_files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        pe_writer::merge_res_files_into_pe(pe, &refs)
    }
}

/// Build the `&[&coff::Object]` slice the writer consumes from the current
/// `slots` plan (which interleaves borrowed `Input::Object` references and
/// owned decoded objects). Decoded objects appended *after* the initial
/// slot plan (i.e. archive-pulled members) are concatenated to the end.
fn build_object_slice<'o>(
    inputs: &'o [Input<'o>],
    slots: &[ObjSlot],
    decoded: &'o [coff::Object],
) -> Vec<&'o coff::Object> {
    let mut out: Vec<&coff::Object> = Vec::with_capacity(slots.len() + decoded.len());
    // First: the originally-planned slots (preserves input order for the
    // non-archive inputs — matches the previous link() behaviour).
    for s in slots {
        match *s {
            ObjSlot::Borrowed(i) => match &inputs[i] {
                Input::Object(o) => out.push(*o),
                _ => unreachable!("Borrowed slot must reference Input::Object"),
            },
            ObjSlot::Owned(i) => out.push(&decoded[i]),
        }
    }
    // Then: any decoded entries not referenced by a slot (the archive
    // pull-ins). Use a small set lookup since `decoded.len()` is bounded by
    // the total archive size — fine for S1c-scale.
    let mut referenced: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for s in slots {
        if let ObjSlot::Owned(i) = *s {
            referenced.insert(i);
        }
    }
    for (i, obj) in decoded.iter().enumerate() {
        if !referenced.contains(&i) {
            out.push(obj);
        }
    }
    out
}

// Slot enum kept at module scope (referenced by `build_object_slice`'s
// caller-supplied slice). The `link()` body re-aliases this for its local
// builder convenience.
type ObjSlot = Slot;

#[derive(Debug, Clone, Copy)]
enum Slot {
    Borrowed(usize),
    Owned(usize),
}

#[derive(Debug)]
struct ArchiveTraceEvent {
    symbol: String,
    archive: String,
    member: String,
}

fn write_archive_trace(
    path: Option<&std::path::Path>,
    events: &[ArchiveTraceEvent],
) -> Result<(), LinkError> {
    let Some(path) = path else {
        return Ok(());
    };

    use std::fmt::Write as _;
    let mut text = String::from("symbol\tarchive\tmember\n");
    for event in events {
        writeln!(
            &mut text,
            "{}\t{}\t{}",
            trace_field(&event.symbol),
            trace_field(&event.archive),
            trace_field(&event.member)
        )
        .expect("write to String");
    }
    std::fs::write(path, text).map_err(|e| {
        LinkError::Internal(format!(
            "cannot write archive trace '{}': {e}",
            path.display()
        ))
    })
}

fn trace_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\t' | '\r' | '\n' => ' ',
            _ => ch,
        })
        .collect()
}

/// Collect the names of every UNDEFINED EXTERNAL across `objects` that is
/// NOT already defined elsewhere in `objects` and NOT a Win32 import (the
/// latter resolve via the [`pe_writer`] IAT, not via archives).
///
/// `__imp_<name>` symbols are also excluded — they are Win32 import
/// references handled by the IAT slot map, not archive members.
fn collect_unresolved_externals<'a>(
    objects: &[&coff::Object],
    extra_roots: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    use coff::{SectionRef, StorageClass, SymName};
    // Helper: render a symbol's name. Mirrors pe_writer::symbol_name_string.
    let name_of = |sym: &coff::Symbol, strtab: &coff::StringTable| -> String {
        match &sym.name {
            SymName::Short(arr) => {
                let end = arr.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&arr[..end]).into_owned()
            }
            SymName::Long(off) => strtab
                .get_str(*off)
                .map(|s| s.to_string())
                .unwrap_or_default(),
        }
    };

    // Defined-symbol set: every EXTERNAL/WEAK section or absolute definition.
    // WeakExternal section definitions are real definitions in mdbcc COFF:
    // they participate in COMDAT folding and must stop both archive re-pulls
    // and synthetic root pulls once a member has satisfied the symbol.
    let mut defined: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for obj in objects {
        for sym in &obj.symbols {
            if sym.storage != StorageClass::External && sym.storage != StorageClass::WeakExternal {
                continue;
            }
            if matches!(sym.section, SectionRef::Undefined) {
                continue;
            }
            let n = name_of(sym, &obj.strtab);
            if !n.is_empty() {
                defined.insert(n);
            }
        }
    }

    // Unresolved: every UNDEFINED EXTERNAL whose name is not in `defined`
    // and not a Win32 import (those resolve via the IAT, not archives).
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for obj in objects {
        for sym in &obj.symbols {
            if sym.storage != StorageClass::External && sym.storage != StorageClass::WeakExternal {
                continue;
            }
            if !matches!(sym.section, SectionRef::Undefined) {
                continue;
            }
            let n = name_of(sym, &obj.strtab);
            if n.is_empty() {
                continue;
            }
            // `__imp_<x>` is a Win32 import marker — resolved against the
            // IAT, never via an archive.
            if let Some(stripped) = n.strip_prefix("__imp_") {
                if pe_writer::is_win32_import(stripped) {
                    continue;
                }
                // `__imp_*` whose stripped name is not a Win32 import we
                // currently lack a way to dispatch — leave it in the
                // unresolved set so write_pe_from_objects can fail loud.
                // (No mdbcc test exercises this today; it would surface as
                // a malformed user object.)
            } else if pe_writer::is_win32_import(&n) {
                // Plain `kernel32` name (no __imp_) — resolved by the
                // pe_writer's IAT path. Skip.
                continue;
            }
            if defined.contains(&n) {
                continue;
            }
            out.insert(n);
        }
    }
    for n in extra_roots {
        if !n.is_empty() && !defined.contains(n) && !pe_writer::is_win32_import(n) {
            out.insert(n.to_string());
        }
    }
    out.into_iter().collect()
}

fn archive_entry_root(opts: &LinkOpts) -> String {
    match (opts.entry.as_deref(), opts.subsystem) {
        (Some(n), _) => n.to_string(),
        (None, Subsystem::Console) => "main".to_string(),
        (None, Subsystem::Gui) => "WinMain".to_string(),
    }
}

/// Merge a parsed [`RcUnit`] into an already-built PE. Thin wrapper around
/// the legacy `build_rsrc` + section-appending logic; expose so
/// `compile.rs` can keep its rc_unit parameter behaviour unchanged.
///
/// S1c.3 limitation: the wrapper appends `.rsrc` as a sixth section to a
/// PE that was built without one. The full multi-input merge (multiple
/// `.res` inputs combined into one `.rsrc`) is S1c.4+ work.
pub fn merge_rsrc_unit(pe: Vec<u8>, rc: &RcUnit) -> Result<Vec<u8>, LinkError> {
    pe_writer::merge_rsrc_into_pe(pe, rc)
}
