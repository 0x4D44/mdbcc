//! S1c.7 — MS-format static library (`.lib`) archive reader.
//!
//! mdlink ingests Microsoft-style `!<arch>\n` archives via [`Input::Archive`].
//! The archive carries N member files (each a COFF or OMF `.obj`) plus an
//! up-front symbol index that maps every PUBDEF in every member to the
//! offset of the defining member's header. The linker uses the index to pull
//! exactly the members it needs to resolve unresolved externals; unreferenced
//! members never enter the link.
//!
//! ## File structure
//!
//! ```text
//! "!<arch>\n"                          (8 bytes — signature)
//! [member-header] [member-data]        (60 + Size bytes; \n pad if odd)
//! ...
//! ```
//!
//! Each 60-byte ASCII header is:
//!
//! ```text
//! [0..16]   Name            (space-padded; long names use "/<dec_offset>")
//! [16..28]  ModTime         (decimal; ignored)
//! [28..34]  OwnerID         (ignored)
//! [34..40]  GroupID         (ignored)
//! [40..48]  Mode            (octal; ignored)
//! [48..58]  Size            (decimal — member-data byte count)
//! [58..60]  "`\n"           (end-mark)
//! ```
//!
//! Member data is `Size` bytes; padded with a single `\n` when `Size` is odd
//! so the next header starts on an even boundary.
//!
//! ## Special members (canonical MS order)
//!
//! 1. **`"/"`** — First Linker Member. Big-endian symbol index (Unix-ar
//!    legacy). `u32` symbol count, then `count` `u32` member offsets (one
//!    per symbol), then `count` NUL-terminated symbol names.
//! 2. **`"/"`** (again) — Second Linker Member. Little-endian symbol index
//!    with a more efficient layout: `u32` member count `M`, `u32[M]` member
//!    offsets, `u32` symbol count `S`, `u16[S]` 1-based member indices,
//!    `S` NUL-terminated symbol names.
//! 3. **`"//"`** — Longnames Member. Concatenated NUL-terminated names for
//!    members whose name exceeds the 16-byte slot; member headers with name
//!    `"/<dec>"` reference offset `dec` into this blob.
//!
//! mdlink prefers the **second** linker member when present (lower CPU cost
//! to read; every modern `.lib` includes it). The first linker member is
//! decoded as a fallback when only it is present (rare; some legacy tools).
//!
//! ## Out of scope
//!
//! - **GNU thin archives** (`!<thin>\n`): the data lives in separate files
//!   referenced by the header. Rejected with [`ArchiveError::BadSignature`].
//! - **BSD `__.SYMDEF`** index format: produced by some Apple toolchains;
//!   not used by Windows producers. We never see it from MS `lib.exe`,
//!   Borland TLIB, or LLD's `lld-link /lib`. Rejected as a malformed second
//!   linker member if encountered.
//!
//! Risk R20 (HLD §11) — both rejection paths emit a clear error rather than
//! silently mis-parsing.

#![allow(dead_code)]

use std::fmt;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A parsed MS-format archive. Holds every member's resolved name and raw
/// bytes plus a flat `(symbol, member_offset)` index built from whichever
/// linker member was present (second preferred; first as fallback).
///
/// Memory: every member is materialised as an owned `Vec<u8>` at read time.
/// For S1c.7 the archives we link against (Borland's `\BC45\LIB\*.LIB`) are
/// at most a few MB; lazy loading is filed as a future S5+ optimisation if
/// memory pressure ever motivates it.
#[derive(Debug, Default)]
pub struct Archive {
    /// Members in encounter order, **excluding** the three special members
    /// (`/`, `/`, `//`). Caller-facing indexing is into this vector.
    members: Vec<ArchiveMember>,
    /// `(symbol_name, member_offset_within_archive)` pairs from the linker
    /// member. The offset references the original archive bytes; we map it
    /// to `members[i]` via [`Archive::find_member_for_symbol`] (which scans
    /// for the matching `ArchiveMember::offset`).
    symbol_index: Vec<(String, u32)>,
}

/// One regular archive member (i.e. a `.obj` file embedded in the `.lib`).
#[derive(Debug, Clone)]
pub struct ArchiveMember {
    /// Resolved name (longnames-aware — names that started life as `/<dec>`
    /// have already been substituted with the corresponding longnames blob
    /// entry).
    name: String,
    /// Byte offset of this member's **header** within the original archive
    /// bytes. The symbol index points at this offset.
    offset: u32,
    /// Member payload (the embedded COFF or OMF `.obj` bytes). Does NOT
    /// include the 60-byte member header or the trailing `\n` pad byte.
    data: Vec<u8>,
}

impl ArchiveMember {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn offset(&self) -> u32 {
        self.offset
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Member format sniff result. See [`Archive::detect_member_format`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberFormat {
    /// COFF, IMAGE_FILE_MACHINE_I386 (`0x014C`; first byte `0x4C`).
    CoffI386,
    /// COFF, IMAGE_FILE_MACHINE_AMD64 (`0x8664`; first byte `0x64`).
    CoffAmd64,
    /// OMF — first byte is a THEADR record type (`0x80`).
    Omf,
    /// Anything else (empty member, import-descriptor pseudo-member,
    /// unknown machine). The caller decides whether to reject or skip.
    Unknown,
}

/// Errors the archive reader can raise. Each variant is a distinct failure
/// shape so callers can attribute the cause; `Display` produces a one-line
/// human-readable message suitable for the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// First 8 bytes are not `"!<arch>\n"`. Includes GNU `!<thin>\n` (we
    /// reject thin archives explicitly).
    BadSignature,
    /// Premature end-of-input — header or member data extends past the end
    /// of the archive bytes.
    Truncated,
    /// A member header's `Size` field could not be parsed, or its end-mark
    /// (\x60\x0a) was missing.
    BadMemberHeader,
    /// Symbol index in the first or second linker member is malformed
    /// (truncated count, offset out of range, missing NUL terminator).
    BadSymbolIndex,
    /// A member's name was `/<dec>` but `dec` is past the end of the
    /// longnames member (or no longnames member existed).
    LongnamesOutOfBounds,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::BadSignature => {
                write!(f, "not an MS-format archive (expected '!<arch>\\n' magic)")
            }
            ArchiveError::Truncated => write!(f, "archive file truncated"),
            ArchiveError::BadMemberHeader => write!(f, "malformed archive member header"),
            ArchiveError::BadSymbolIndex => write!(f, "malformed archive symbol index"),
            ArchiveError::LongnamesOutOfBounds => {
                write!(f, "archive longnames offset out of range")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SIGNATURE: &[u8; 8] = b"!<arch>\n";
const HEADER_SIZE: usize = 60;
const NAME_OFFSET: usize = 0;
const NAME_LEN: usize = 16;
const SIZE_OFFSET: usize = 48;
const SIZE_LEN: usize = 10;
const ENDMARK_OFFSET: usize = 58;
const ENDMARK: &[u8; 2] = b"\x60\x0a"; // back-tick, newline

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

impl Archive {
    /// Parse `bytes` as an MS-format `.lib` archive. Validates the magic,
    /// walks every member, separates the linker / longnames specials from
    /// the real `.obj` members, and builds the symbol index for fast lookup.
    ///
    /// On success the returned [`Archive`] owns copies of every member's
    /// data (no borrow back into `bytes`).
    pub fn read(bytes: &[u8]) -> Result<Self, ArchiveError> {
        if bytes.len() < SIGNATURE.len() {
            return Err(ArchiveError::Truncated);
        }
        if &bytes[..SIGNATURE.len()] != SIGNATURE {
            return Err(ArchiveError::BadSignature);
        }

        // Walk the archive: collect (raw_name, offset_of_header, data_slice)
        // for every member in encounter order. Linker-/longnames-special
        // members are extracted *during* the walk (their bytes are needed to
        // resolve longnames-based names on the regular members).
        let mut raw_members: Vec<RawMember<'_>> = Vec::new();
        let mut cursor: usize = SIGNATURE.len();
        while cursor < bytes.len() {
            // Skip the 1-byte `\n` pad some writers leave between members
            // (when a previous payload had odd Size). Defensive: the cursor
            // is supposed to already point at a header after the size-pad
            // bump below, but some archives emit a leading newline before
            // the FIRST header that doesn't match the canonical layout.
            // Pad-skip only ONE byte and only when it's `\n` (matches what
            // lld-link tolerates).
            if bytes[cursor] == b'\n' {
                cursor += 1;
                if cursor >= bytes.len() {
                    break;
                }
            }
            if cursor + HEADER_SIZE > bytes.len() {
                return Err(ArchiveError::Truncated);
            }
            let header_offset = cursor;
            let header = &bytes[cursor..cursor + HEADER_SIZE];
            if &header[ENDMARK_OFFSET..ENDMARK_OFFSET + 2] != ENDMARK {
                return Err(ArchiveError::BadMemberHeader);
            }

            // Name: trim trailing spaces. Don't truncate at NUL — MS uses
            // space-padded names (a NUL in the name slot would itself be a
            // malformed header).
            let raw_name = parse_name_slot(&header[NAME_OFFSET..NAME_OFFSET + NAME_LEN])?;

            // Size: decimal ASCII; trim trailing spaces and parse.
            let size = parse_decimal(&header[SIZE_OFFSET..SIZE_OFFSET + SIZE_LEN])
                .ok_or(ArchiveError::BadMemberHeader)?;
            let data_start = cursor + HEADER_SIZE;
            let data_end = data_start
                .checked_add(size)
                .ok_or(ArchiveError::Truncated)?;
            if data_end > bytes.len() {
                return Err(ArchiveError::Truncated);
            }
            let data = &bytes[data_start..data_end];

            raw_members.push(RawMember {
                raw_name,
                offset: header_offset as u32,
                data,
            });

            // Advance past the data, plus one byte of `\n` pad if `size` is odd.
            cursor = data_end;
            if size % 2 == 1 && cursor < bytes.len() && bytes[cursor] == b'\n' {
                cursor += 1;
            }
        }

        // The MS canonical order is:
        //   raw_members[0] = "/"  — first linker member  (big-endian index)
        //   raw_members[1] = "/"  — second linker member (little-endian index)
        //   raw_members[2] = "//" — longnames blob
        //   raw_members[3..] = the real .obj members
        //
        // Some archives (small, hand-built, or older toolchains) omit the
        // second linker member or the longnames blob. Walk the head of the
        // list defensively rather than assuming exact positions.
        let mut first_linker: Option<&[u8]> = None;
        let mut second_linker: Option<&[u8]> = None;
        let mut longnames: &[u8] = &[];
        let mut head_consumed = 0usize;

        for (i, m) in raw_members.iter().enumerate() {
            if m.raw_name == "/" {
                if first_linker.is_none() {
                    first_linker = Some(m.data);
                } else if second_linker.is_none() {
                    second_linker = Some(m.data);
                } else {
                    // Three or more "/"-named specials is not standard; stop
                    // consuming the head and treat the third as a real
                    // (oddly-named) member — though in practice this never
                    // happens for MS archives.
                    head_consumed = i;
                    break;
                }
                head_consumed = i + 1;
            } else if m.raw_name == "//" {
                longnames = m.data;
                head_consumed = i + 1;
            } else {
                head_consumed = i;
                break;
            }
        }

        // Resolve member names for the regular members. A name starting with
        // `/` followed by digits is a longnames reference: `/<dec>` means
        // "look up the NUL-terminated name starting at byte `dec` of the
        // longnames blob". A bare `/` is one of the specials and was already
        // consumed above.
        let mut members: Vec<ArchiveMember> = Vec::new();
        for raw in &raw_members[head_consumed..] {
            // Some archives terminate the name with `/` (per the ar format
            // convention to disambiguate trailing whitespace). Strip it.
            let resolved = if let Some(rest) = raw.raw_name.strip_prefix('/') {
                if rest.is_empty() {
                    // Bare "/" past the special-member head — treat as an
                    // anonymous member with the literal name "/".
                    raw.raw_name.clone()
                } else {
                    // `/<dec>` — longnames lookup. The decimal MUST parse;
                    // anything else is malformed. (Borland and MS both emit
                    // only `/<dec>` and bare `/`.)
                    let off: usize = rest.parse().map_err(|_| ArchiveError::BadMemberHeader)?;
                    if off >= longnames.len() {
                        return Err(ArchiveError::LongnamesOutOfBounds);
                    }
                    let end = longnames[off..]
                        .iter()
                        .position(|&b| b == 0 || b == b'\n' || b == b'/')
                        .map(|p| off + p)
                        .unwrap_or(longnames.len());
                    String::from_utf8_lossy(&longnames[off..end]).into_owned()
                }
            } else {
                // Inline name — may have a trailing `/` for ar-convention
                // disambiguation; strip it.
                raw.raw_name
                    .strip_suffix('/')
                    .map(str::to_string)
                    .unwrap_or_else(|| raw.raw_name.clone())
            };
            members.push(ArchiveMember {
                name: resolved,
                offset: raw.offset,
                data: raw.data.to_vec(),
            });
        }

        // Build the symbol index. Prefer the second linker member (modern MS
        // format); fall back to the first (legacy / partial archives).
        let symbol_index = if let Some(sl) = second_linker {
            parse_second_linker_member(sl)?
        } else if let Some(fl) = first_linker {
            parse_first_linker_member(fl)?
        } else {
            // No symbol index at all. Linkers still accept this (every
            // member must be force-included), but we treat it as a degraded
            // archive with no entries — `find_member_for_symbol` returns
            // None for every query. For S1c.7 this is sufficient: every
            // archive in our test set has an index.
            Vec::new()
        };

        Ok(Archive {
            members,
            symbol_index,
        })
    }

    /// Number of regular `.obj` members in this archive (excludes the
    /// linker- and longnames-special members).
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Borrow the resolved member name at index `idx`.
    pub fn member_name(&self, idx: usize) -> &str {
        &self.members[idx].name
    }

    /// Borrow the raw `.obj` bytes for member at index `idx`. The bytes are
    /// the COFF or OMF payload (no archive header / pad bytes).
    pub fn member_bytes(&self, idx: usize) -> &[u8] {
        &self.members[idx].data
    }

    /// Iterate every `(symbol_name, member_header_offset)` pair from the
    /// symbol index in the order it appeared in the archive.
    pub fn symbols(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.symbol_index
            .iter()
            .map(|(name, offset)| (name.as_str(), *offset))
    }

    /// Look up `sym` in the symbol index; if found, return the index of the
    /// `.obj` member that defines it. Linear scan of the symbol index, then
    /// match the recorded offset against the member list. The MS format
    /// inflates the symbol-index size more than the member list, so a
    /// linear sweep is acceptable for archives of the size we link (≤ a few
    /// thousand symbols).
    ///
    /// First match wins — matches link.exe / lld-link behaviour when a
    /// symbol is multiply defined within one archive (rare, but happens
    /// when an archive is concatenated from per-TU partial archives during
    /// CRT staging).
    pub fn find_member_for_symbol(&self, sym: &str) -> Option<usize> {
        let target_offset = self
            .symbol_index
            .iter()
            .find_map(|(name, off)| if name == sym { Some(*off) } else { None })?;
        self.members.iter().position(|m| m.offset == target_offset)
    }

    /// Heuristic format detection for a member. Sniffs the first byte
    /// (COFF machine code's low byte) and falls back to OMF / Unknown.
    ///
    /// COFF: IMAGE_FILE_HEADER starts with the 16-bit Machine field, little-
    /// endian. `IMAGE_FILE_MACHINE_I386 = 0x014C` ⇒ first byte `0x4C`.
    /// `IMAGE_FILE_MACHINE_AMD64 = 0x8664` ⇒ first byte `0x64`. Other
    /// machines (ARM64, etc.) are out of mdbcc's scope today and surface
    /// as [`MemberFormat::Unknown`].
    ///
    /// OMF: every Borland-emitted module begins with a THEADR record whose
    /// type byte is `0x80`. The 2-byte length field that follows is
    /// little-endian; we don't sniff it but verify the THEADR-ish shape via
    /// the leading `0x80` only.
    pub fn detect_member_format(&self, idx: usize) -> MemberFormat {
        let data = self.member_bytes(idx);
        match data.first() {
            Some(&0x4C) if data.len() >= 2 && data[1] == 0x01 => MemberFormat::CoffI386,
            Some(&0x64) if data.len() >= 2 && data[1] == 0x86 => MemberFormat::CoffAmd64,
            Some(&0x80) => MemberFormat::Omf,
            _ => MemberFormat::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Temporary view of a member during the walk; we promote selected entries
/// into the owned [`ArchiveMember`] list once we've decoded enough to know
/// what's a special and what's a real `.obj`.
struct RawMember<'a> {
    raw_name: String,
    offset: u32,
    data: &'a [u8],
}

/// Parse a 16-byte name slot. The MS / ar convention is space-padded ASCII
/// (no NUL); trim trailing spaces and convert to a String. We accept (and
/// trim) a stray NUL too so older toolchains that mix conventions don't
/// trip the reader.
fn parse_name_slot(slot: &[u8]) -> Result<String, ArchiveError> {
    if slot.len() != NAME_LEN {
        return Err(ArchiveError::BadMemberHeader);
    }
    let end = slot
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map(|p| p + 1)
        .unwrap_or(0);
    let bytes = &slot[..end];
    // ASCII range only; non-ASCII in a member name would indicate a wildly
    // broken archive. Lossy decode keeps the reader strict-on-shape but
    // permissive-on-charset (we only ever compare against ASCII anyway).
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Parse a fixed-width decimal field (trailing spaces tolerated). Returns
/// None when the field is empty or non-numeric.
fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map(|p| p + 1)
        .unwrap_or(0);
    if end == 0 {
        return Some(0);
    }
    let s = std::str::from_utf8(&bytes[..end]).ok()?;
    s.parse::<usize>().ok()
}

/// Parse the first linker member's symbol index (big-endian, Unix-ar
/// flavour). Layout:
///
/// ```text
///   u32_be  count
///   u32_be[count]  member_offsets
///   ...            count NUL-terminated symbol names
/// ```
fn parse_first_linker_member(body: &[u8]) -> Result<Vec<(String, u32)>, ArchiveError> {
    if body.len() < 4 {
        return Err(ArchiveError::BadSymbolIndex);
    }
    let count = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let offsets_end = 4usize
        .checked_add(count.checked_mul(4).ok_or(ArchiveError::BadSymbolIndex)?)
        .ok_or(ArchiveError::BadSymbolIndex)?;
    if offsets_end > body.len() {
        return Err(ArchiveError::BadSymbolIndex);
    }
    let mut offsets = Vec::with_capacity(count);
    for i in 0..count {
        let base = 4 + i * 4;
        offsets.push(u32::from_be_bytes([
            body[base],
            body[base + 1],
            body[base + 2],
            body[base + 3],
        ]));
    }
    let names_blob = &body[offsets_end..];
    let names = parse_name_strings(names_blob, count)?;
    Ok(names.into_iter().zip(offsets).collect())
}

/// Parse the second linker member's symbol index (little-endian, MS
/// flavour). Layout:
///
/// ```text
///   u32_le  num_members  (M)
///   u32_le[M]  member_offsets
///   u32_le  num_symbols  (S)
///   u16_le[S]  member_indices  (1-based into member_offsets; 0 ⇒ invalid)
///   ...        S NUL-terminated symbol names
/// ```
///
/// Returns `(symbol_name, member_offset)` pairs. The member_offset is the
/// actual byte offset into the archive (resolved via member_indices[i]).
fn parse_second_linker_member(body: &[u8]) -> Result<Vec<(String, u32)>, ArchiveError> {
    let mut p = 0usize;
    let read_u32 = |body: &[u8], p: &mut usize| -> Result<u32, ArchiveError> {
        if *p + 4 > body.len() {
            return Err(ArchiveError::BadSymbolIndex);
        }
        let v = u32::from_le_bytes([body[*p], body[*p + 1], body[*p + 2], body[*p + 3]]);
        *p += 4;
        Ok(v)
    };
    let read_u16 = |body: &[u8], p: &mut usize| -> Result<u16, ArchiveError> {
        if *p + 2 > body.len() {
            return Err(ArchiveError::BadSymbolIndex);
        }
        let v = u16::from_le_bytes([body[*p], body[*p + 1]]);
        *p += 2;
        Ok(v)
    };

    let num_members = read_u32(body, &mut p)? as usize;
    let mut member_offsets: Vec<u32> = Vec::with_capacity(num_members);
    for _ in 0..num_members {
        member_offsets.push(read_u32(body, &mut p)?);
    }
    let num_symbols = read_u32(body, &mut p)? as usize;
    let mut indices: Vec<u16> = Vec::with_capacity(num_symbols);
    for _ in 0..num_symbols {
        indices.push(read_u16(body, &mut p)?);
    }
    let names = parse_name_strings(&body[p..], num_symbols)?;

    let mut out = Vec::with_capacity(num_symbols);
    for (name, idx) in names.into_iter().zip(indices) {
        // 1-based into member_offsets; 0 is "no defining member" per the MS
        // spec (sometimes seen for the auxiliary `__NULL_IMPORT_DESCRIPTOR`
        // marker). Skip those — the resulting Archive has no symbol entry
        // for them, which means `find_member_for_symbol` returns None and
        // the linker falls through to "unresolved" (correct behaviour).
        if idx == 0 {
            continue;
        }
        let off = *member_offsets
            .get((idx as usize) - 1)
            .ok_or(ArchiveError::BadSymbolIndex)?;
        out.push((name, off));
    }
    Ok(out)
}

/// Pull `count` NUL-terminated strings out of `blob`. Returns
/// [`ArchiveError::BadSymbolIndex`] when fewer than `count` NUL bytes are
/// present.
fn parse_name_strings(blob: &[u8], count: usize) -> Result<Vec<String>, ArchiveError> {
    let mut out = Vec::with_capacity(count);
    let mut start = 0usize;
    for _ in 0..count {
        let end = blob[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(ArchiveError::BadSymbolIndex)?;
        let s = String::from_utf8_lossy(&blob[start..start + end]).into_owned();
        out.push(s);
        start += end + 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Builder (test-only helper)
// ---------------------------------------------------------------------------

/// One symbol a static-library member contributes to the archive symbol
/// index, keeping the linkage strength so a librarian can prefer a strong
/// definition over an earlier weak one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPubdef {
    pub name: String,
    pub storage: crate::coff::StorageClass,
}

/// The symbols a static-library member contributes to the archive symbol
/// index — its PUBDEFs (DEFINED external symbols).
///
/// A symbol qualifies when it is `External` **or** `WeakExternal` AND lives
/// in a real section (`SectionRef::Section`). Both linkage classes index:
/// mdbcc emits every vague-linkage definition (out-of-line member methods,
/// vtables, template instantiations) as a WEAK section-defined symbol so
/// cross-TU duplicates COMDAT-fold at link. A member whose definitions are
/// ALL weak (e.g. OWL's EVENTHAN.o, where `TEventHandler::Find`/`Dispatch`/
/// `SearchEntries` are weak) must STILL be advertised in the index or the
/// linker — which pulls members solely from the index — never pulls it, and
/// the whole response-table base goes unresolved. Undefined symbols
/// (section 0, including the `WeakExternal` *reference* form) and non-external
/// locals are excluded — they aren't definitions.
pub fn member_pubdefs(obj: &crate::coff::Object) -> Vec<String> {
    member_pubdefs_with_storage(obj)
        .into_iter()
        .map(|p| p.name)
        .collect()
}

/// Same scan as [`member_pubdefs`], but preserves whether each definition is
/// strong (`External`) or weak (`WeakExternal`).
pub fn member_pubdefs_with_storage(obj: &crate::coff::Object) -> Vec<MemberPubdef> {
    use crate::coff::{SectionRef, StorageClass, SymName};
    let mut out = Vec::new();
    for s in &obj.symbols {
        if matches!(
            s.storage,
            StorageClass::External | StorageClass::WeakExternal
        ) && matches!(s.section, SectionRef::Section(_))
        {
            let n = match &s.name {
                SymName::Short(a) => {
                    let end = a.iter().position(|&b| b == 0).unwrap_or(8);
                    String::from_utf8_lossy(&a[..end]).into_owned()
                }
                SymName::Long(off) => obj
                    .strtab
                    .get_str(*off)
                    .map(str::to_string)
                    .unwrap_or_default(),
            };
            if !n.is_empty() {
                out.push(MemberPubdef {
                    name: n,
                    storage: s.storage,
                });
            }
        }
    }
    out
}

/// Build an MS-format archive byte stream from a list of `(name, bytes)`
/// member pairs. Used by tests to construct hand-crafted archives without
/// shelling out to `lib.exe` (which we don't have on the test runner) — the
/// format is well-specified and small, so a Rust builder is the cleanest
/// way to construct test fixtures.
///
/// Emits the canonical MS layout:
///   - 8-byte signature
///   - first linker member (big-endian symbol index)
///   - second linker member (little-endian symbol index — what mdlink reads)
///   - longnames member (for names > 15 chars — empty when all names fit)
///   - the supplied members in input order
///
/// `member_symbols[i]` is the list of symbol names defined by `members[i]`.
/// Each symbol enters both linker members' indices pointing at members[i].
pub fn build_archive_bytes(
    members: &[(String, Vec<u8>)],
    member_symbols: &[Vec<String>],
) -> Vec<u8> {
    assert_eq!(
        members.len(),
        member_symbols.len(),
        "members and member_symbols must have matching length"
    );

    // Compose long-name table. Any name longer than 15 bytes (the 16-byte
    // slot needs a trailing `/`) is replaced with `/<dec_offset>`. Short
    // names are inlined as `<name>/` (the trailing `/` follows ar
    // convention so trailing spaces in 16-byte slots are unambiguous).
    let mut longnames: Vec<u8> = Vec::new();
    let mut header_names: Vec<String> = Vec::with_capacity(members.len());
    for (name, _) in members {
        if name.len() <= 15 {
            header_names.push(format!("{}/", name));
        } else {
            let off = longnames.len();
            longnames.extend_from_slice(name.as_bytes());
            longnames.push(0);
            header_names.push(format!("/{}", off));
        }
    }

    // We have to know each member's offset within the archive BEFORE we
    // emit the linker members (the indices reference those offsets). We
    // compute offsets in a planning pass, then emit bytes.
    //
    // Layout helper: `member_record_size` includes the 60-byte header, the
    // payload, and the (optional) 1-byte `\n` pad if payload size is odd.
    fn member_record_size(payload_len: usize) -> usize {
        HEADER_SIZE + payload_len + (payload_len & 1)
    }

    // Plan the linker-member sizes so we can compute each real member's
    // offset. Symbols are emitted in input order, flat across members.
    let total_symbols: usize = member_symbols.iter().map(Vec::len).sum();
    let symname_blob_size: usize = member_symbols.iter().flatten().map(|s| s.len() + 1).sum();

    let first_linker_size = 4 + total_symbols * 4 + symname_blob_size;
    let second_linker_size = 4 + members.len() * 4 + 4 + total_symbols * 2 + symname_blob_size;
    let longnames_size = longnames.len();

    // Compute the offset of each real member's header. Specials come first
    // (first linker, second linker, longnames), each in their own member
    // record.
    let mut cursor = SIGNATURE.len()
        + member_record_size(first_linker_size)
        + member_record_size(second_linker_size)
        + member_record_size(longnames_size);
    let mut member_header_offsets: Vec<u32> = Vec::with_capacity(members.len());
    for (_, payload) in members {
        member_header_offsets.push(cursor as u32);
        cursor += member_record_size(payload.len());
    }

    // Now emit bytes.
    let mut out: Vec<u8> = Vec::with_capacity(cursor);
    out.extend_from_slice(SIGNATURE);

    // --- First linker member (big-endian, name "/") -------------------
    let mut fl: Vec<u8> = Vec::with_capacity(first_linker_size);
    fl.extend_from_slice(&(total_symbols as u32).to_be_bytes());
    for (mi, syms) in member_symbols.iter().enumerate() {
        let off = member_header_offsets[mi];
        for _ in syms {
            fl.extend_from_slice(&off.to_be_bytes());
        }
    }
    for syms in member_symbols {
        for s in syms {
            fl.extend_from_slice(s.as_bytes());
            fl.push(0);
        }
    }
    assert_eq!(fl.len(), first_linker_size);
    emit_member(&mut out, "/", &fl);

    // --- Second linker member (little-endian, name "/") ----------------
    let mut sl: Vec<u8> = Vec::with_capacity(second_linker_size);
    sl.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for &off in &member_header_offsets {
        sl.extend_from_slice(&off.to_le_bytes());
    }
    sl.extend_from_slice(&(total_symbols as u32).to_le_bytes());
    for (mi, syms) in member_symbols.iter().enumerate() {
        let one_based = (mi as u16) + 1;
        for _ in syms {
            sl.extend_from_slice(&one_based.to_le_bytes());
        }
    }
    for syms in member_symbols {
        for s in syms {
            sl.extend_from_slice(s.as_bytes());
            sl.push(0);
        }
    }
    assert_eq!(sl.len(), second_linker_size);
    emit_member(&mut out, "/", &sl);

    // --- Longnames member ---------------------------------------------
    emit_member(&mut out, "//", &longnames);

    // --- Real members --------------------------------------------------
    for (i, (_, payload)) in members.iter().enumerate() {
        // Assert our planning matches reality.
        assert_eq!(
            out.len() as u32,
            member_header_offsets[i],
            "planning mismatch at member {i}"
        );
        emit_member(&mut out, &header_names[i], payload);
    }

    out
}

/// Write a single member to `out`: 60-byte header + payload + optional pad.
/// `name` is rendered verbatim (must already include any trailing `/`).
fn emit_member(out: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let mut header = [b' '; HEADER_SIZE];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(NAME_LEN);
    header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    // ModTime "0", uid "0", gid "0", mode "0", size "N" — all space-padded.
    // We zero them but match the layout: leftmost char "0", rest spaces.
    header[16] = b'0';
    header[28] = b'0';
    header[34] = b'0';
    header[40] = b'0';
    let size_str = payload.len().to_string();
    let size_bytes = size_str.as_bytes();
    header[SIZE_OFFSET..SIZE_OFFSET + size_bytes.len()].copy_from_slice(size_bytes);
    header[ENDMARK_OFFSET..ENDMARK_OFFSET + 2].copy_from_slice(ENDMARK);
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        out.push(b'\n');
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest legitimate archive: one tiny member with one symbol.
    /// Exercises round-tripping of [`build_archive_bytes`] against
    /// [`Archive::read`].
    #[test]
    fn round_trip_single_member() {
        let payload: Vec<u8> = vec![0x64, 0x86, 0xCA, 0xFE]; // mimics COFF AMD64
        let members = vec![("foo.obj".to_string(), payload.clone())];
        let syms = vec![vec!["foo".to_string()]];
        let bytes = build_archive_bytes(&members, &syms);

        let ar = Archive::read(&bytes).expect("Archive::read");
        assert_eq!(ar.member_count(), 1);
        assert_eq!(ar.member_name(0), "foo.obj");
        assert_eq!(ar.member_bytes(0), payload.as_slice());
        assert_eq!(ar.find_member_for_symbol("foo"), Some(0));
        assert_eq!(ar.find_member_for_symbol("nope"), None);
        let collected: Vec<(&str, u32)> = ar.symbols().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, "foo");
    }

    #[test]
    fn bad_signature_rejected() {
        let bytes = b"not_an_archive_____";
        match Archive::read(bytes).expect_err("should reject") {
            ArchiveError::BadSignature => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn truncated_signature_rejected() {
        let bytes = b"!<arc";
        match Archive::read(bytes).expect_err("should reject") {
            ArchiveError::Truncated => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn detect_member_format_works() {
        // Build three members with different leading bytes.
        let coff_i386: Vec<u8> = vec![0x4C, 0x01, 0x00, 0x00];
        let coff_amd64: Vec<u8> = vec![0x64, 0x86, 0x00, 0x00];
        let omf: Vec<u8> = vec![0x80, 0x05, 0x00, b'a'];
        let members = vec![
            ("i386.obj".to_string(), coff_i386),
            ("amd64.obj".to_string(), coff_amd64),
            ("legacy.obj".to_string(), omf),
        ];
        let syms = vec![
            vec!["a".to_string()],
            vec!["b".to_string()],
            vec!["c".to_string()],
        ];
        let bytes = build_archive_bytes(&members, &syms);
        let ar = Archive::read(&bytes).expect("Archive::read");
        assert_eq!(ar.detect_member_format(0), MemberFormat::CoffI386);
        assert_eq!(ar.detect_member_format(1), MemberFormat::CoffAmd64);
        assert_eq!(ar.detect_member_format(2), MemberFormat::Omf);
    }

    #[test]
    fn longnames_resolve() {
        // A member with a >15-byte name uses the longnames blob.
        let long = "very_long_member_name_above_15.obj".to_string();
        let members = vec![(long.clone(), vec![0x64, 0x86, 0, 0])];
        let syms = vec![vec!["x".to_string()]];
        let bytes = build_archive_bytes(&members, &syms);
        let ar = Archive::read(&bytes).expect("Archive::read");
        assert_eq!(ar.member_count(), 1);
        assert_eq!(ar.member_name(0), long);
        assert_eq!(ar.find_member_for_symbol("x"), Some(0));
    }

    #[test]
    fn multiple_members_and_symbols() {
        let members = vec![
            ("a.obj".to_string(), vec![0x64, 0x86, 1, 2]),
            ("b.obj".to_string(), vec![0x64, 0x86, 3, 4, 5]), // odd size → pad
            ("c.obj".to_string(), vec![0x64, 0x86, 6, 7]),
        ];
        let syms = vec![
            vec!["a1".to_string(), "a2".to_string()],
            vec!["b1".to_string()],
            vec!["c1".to_string(), "c2".to_string(), "c3".to_string()],
        ];
        let bytes = build_archive_bytes(&members, &syms);
        let ar = Archive::read(&bytes).expect("Archive::read");
        assert_eq!(ar.member_count(), 3);
        assert_eq!(ar.find_member_for_symbol("a1"), Some(0));
        assert_eq!(ar.find_member_for_symbol("a2"), Some(0));
        assert_eq!(ar.find_member_for_symbol("b1"), Some(1));
        assert_eq!(ar.find_member_for_symbol("c1"), Some(2));
        assert_eq!(ar.find_member_for_symbol("c2"), Some(2));
        assert_eq!(ar.find_member_for_symbol("c3"), Some(2));
        assert_eq!(ar.find_member_for_symbol("missing"), None);

        // Bytes survive round-trip exactly.
        assert_eq!(ar.member_bytes(0), &[0x64, 0x86, 1, 2]);
        assert_eq!(ar.member_bytes(1), &[0x64, 0x86, 3, 4, 5]);
        assert_eq!(ar.member_bytes(2), &[0x64, 0x86, 6, 7]);
    }
}
