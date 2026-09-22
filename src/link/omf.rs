//! S1c.6 — Borland-flavoured OMF (Microsoft Object Module Format) reader.
//!
//! bcc32 4.52 emits OMF `.obj` files; mdlink ingests them via [`Input::OmfBytes`].
//! This module extends the S1b.6 OMF walker (`tests/support/omf_walker.rs`) with
//! the records mdlink needs to actually *link* OMF — LEDATA / LIDATA payloads
//! and FIXUPP relocations — and provides [`to_coff_object`], the translator
//! that converts a parsed [`OmfImage`] into the [`coff::Object`] shape that
//! [`crate::link::pe_writer::write_pe_from_objects`] consumes.
//!
//! ## Record framing reminder
//!
//! ```text
//! [type:1] [length:2 LE] [body:length-1] [checksum:1]
//! ```
//! The trailing checksum byte is the 2's-complement sum-mod-256 of every
//! other byte in the record. We do NOT validate it — bcc32's output is
//! authoritative; if it sums wrong we have bigger problems than the
//! reader mis-decoding it.
//!
//! Indices in record bodies use Borland's 1-or-2 byte form:
//! - First byte `b`; if `b < 0x80` the index is `b`.
//! - Else the index is `((b & 0x7F) << 8) | next_byte`. (Big-endian
//!   when the high bit is set.)
//!
//! Names are Pascal strings: `[len:1] [bytes:len]` (no NUL terminator).
//!
//! ## Records decoded
//!
//! - **LNAMES** (0x96 / 0x97): name table referenced by SEGDEF / COMDAT.
//! - **SEGDEF** (0x98 / 0x99): segment definitions with name/class/length.
//! - **PUBDEF / LPUBDEF** (0x90 / 0x91 / 0xB6 / 0xB7): public symbols.
//! - **EXTDEF / LEXTDEF** (0x8C / 0xB4): external (undefined) references.
//! - **COMDEF** (0xB0 / 0xB8): communal (BSS-like) symbols.
//! - **COMDAT** (0xC2 / 0xC3): communal data sections.
//! - **LEDATA** (0xA0 / 0xA1): logical enumerated data (raw segment bytes).
//! - **LIDATA** (0xA2 / 0xA3): logical iterated data (RLE-compressed bytes).
//! - **FIXUPP** (0x9C / 0x9D): relocations within LEDATA / LIDATA / COMDAT.
//! - **MODEND** (0x8A / 0x8B): end of module — stops the walk.
//! - **THEADR** (0x80): translator header (source-file name; informational).
//! - **COMENT** (0x88): comment / link directive (mostly ignored).
//! - **GRPDEF** (0x9A / 0x9B): group definitions (decoded but not honoured
//!   except to allow FIXUPP frame-method 1 / group-relative fixups).
//!
//! Records we explicitly skip without warning:
//! - **LINNUM** (0x94 / 0x95): source line-number debug info (S8 work).
//!
//! ## OMF → COFF translation
//!
//! - `_TEXT` (class `CODE`) → `.text`
//! - `_DATA` (class `DATA`) → `.data`
//! - `_BSS` (class `BSS`) → `.bss`
//! - `_RDATA` / `_CONST` / class `CONST` → `.rdata`
//! - Anything else → `SectionName::Custom(name)`
//!
//! PUBDEF → defined `SectionRef::Section(n)` EXTERNAL symbol.
//! EXTDEF → undefined `SectionRef::Undefined` EXTERNAL symbol.
//! COMDEF → defined section symbol with synthesised BSS allocation.
//! FIXUPP → `coff::Reloc { offset, symbol, kind }` against the appropriate
//!   defining or external symbol.
//!
//! ## Machine-mismatch caveat
//!
//! bcc32 4.52 emits **32-bit x86** OMF. mdlink today produces an **AMD64**
//! PE. The OMF reader returns an [`OmfImage`] whose machine code is i386;
//! mdlink's pe_writer rejects non-AMD64 inputs. The structural decode
//! still works end-to-end (OMF→coff::Object); execution requires a 32-bit
//! PE writer that is out of S1c.6 scope.

#![allow(dead_code)]

use std::fmt;

use crate::coff::{
    self, RelocKind, Section, SectionName, SectionRef, StorageClass, SymKind, SymName, Symbol,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed OMF image. Field order matches HLD §3 semantic-content
/// vocabulary; the harness compares mdbcc-COFF symbols against these
/// records by mangled name.
#[derive(Debug, Default)]
pub struct OmfImage {
    /// THEADR-supplied source file name (informational, used for diagnostics).
    pub source: String,
    /// LNAMES table, 1-indexed (entry `[0]` is a sentinel empty name).
    /// Borland references names from SEGDEF / COMDAT by `lnames[idx]`.
    pub lnames: Vec<String>,
    /// SEGDEF records in encounter order.
    pub segments: Vec<Segment>,
    /// GRPDEF records in encounter order.
    pub groups: Vec<Group>,
    /// PUBDEF / LPUBDEF symbol definitions in encounter order. We do not
    /// distinguish local-public (LPUBDEF) from global-public (PUBDEF)
    /// here — the O13 harness needs both, and Borland uses LPUBDEF for
    /// `static` linkage which only differs at the OMF layer.
    pub pubdefs: Vec<Pubdef>,
    /// EXTDEF symbol references (undefined externals) in encounter order.
    pub extdefs: Vec<Extdef>,
    /// COMDEF communal symbols in encounter order.
    pub comdefs: Vec<Comdef>,
    /// COMDAT communal data sections in encounter order.
    pub comdats: Vec<Comdat>,
    /// LEDATA / LIDATA payloads applied to segments (in encounter order).
    /// Each entry records `(segment_idx, offset, bytes)` after iteration
    /// expansion for LIDATA.
    pub data_records: Vec<DataRecord>,
    /// FIXUPP records, one entry per fixup (records are flattened during
    /// decode). Each fixup references its target by FIXUPP rules — see
    /// [`Fixup`].
    pub fixups: Vec<Fixup>,
}

/// One SEGDEF record. `name_idx` / `class_idx` index into `OmfImage.lnames`
/// (1-based). `length` is the SegmentLength field — for 32-bit segments
/// it's a 4-byte LE value (when the 16-bit-segments variant is used, the
/// 2-byte length field is widened by the reader).
#[derive(Debug, Clone)]
pub struct Segment {
    pub name_idx: u16,
    pub class_idx: u16,
    pub length: u32,
    /// Bit 2 of the ACBP attribute byte: 1 = USE32, 0 = USE16. mdlink
    /// rejects USE16 inputs (Win32 OMF is USE32; USE16 is real-mode DOS).
    pub use32: bool,
    /// Initial segment-data buffer. Populated by LEDATA / LIDATA records.
    /// Sized to `length` (zero-init), then LEDATA / LIDATA records write
    /// into the appropriate offset.
    pub data: Vec<u8>,
}

impl Segment {
    /// Resolve `name_idx` against the supplied LNAMES table.
    pub fn name<'a>(&self, lnames: &'a [String]) -> Option<&'a str> {
        lnames.get(self.name_idx as usize).map(|s| s.as_str())
    }
    /// Resolve `class_idx` against the supplied LNAMES table.
    pub fn class<'a>(&self, lnames: &'a [String]) -> Option<&'a str> {
        lnames.get(self.class_idx as usize).map(|s| s.as_str())
    }
}

/// One GRPDEF record. Carries the 1-based name index plus the 1-based
/// segment indices that make up the group. mdlink uses this to interpret
/// FIXUPP frame-method-1 (group-relative) fixups: if every segment in the
/// group is the same logical chunk (e.g. DGROUP = `_DATA + _BSS + _CONST`),
/// the fixup is treated as segment-relative against the group's first
/// segment (a heuristic that is enough for what bcc32 produces).
#[derive(Debug, Clone, Default)]
pub struct Group {
    pub name_idx: u16,
    pub segment_indices: Vec<u16>,
}

/// One PUBDEF / LPUBDEF entry. `segment_idx` is the 1-based segment index
/// from the immediately preceding `OmfImage.segments` table; 0 means
/// "absolute" (no segment). `offset` is the symbol's byte offset within
/// the segment.
#[derive(Debug, Clone)]
pub struct Pubdef {
    pub name: String,
    pub segment_idx: u16,
    pub offset: u32,
    pub type_idx: u16,
}

/// One EXTDEF entry — an undefined external reference to be resolved at
/// link time.
#[derive(Debug, Clone)]
pub struct Extdef {
    pub name: String,
    pub type_idx: u16,
}

/// One COMDEF entry — a communal symbol (Borland uses these for typeinfo +
/// auto-generated destructors so duplicate TUs sharing the same class
/// resolve to a single instance at link time).
#[derive(Debug, Clone)]
pub struct Comdef {
    pub name: String,
    pub type_idx: u16,
    /// Data-segment communal: `count` * `size` bytes of zero-init storage.
    /// Far-communal: `count` is the array length.
    pub count: u32,
    pub size: u32,
}

/// One COMDAT entry — a communal data section.
#[derive(Debug, Clone)]
pub struct Comdat {
    pub name: String,
    pub segment_idx: u16,
    pub offset: u32,
}

/// LEDATA / LIDATA-derived data record. After iteration expansion for
/// LIDATA the two variants are indistinguishable: a flat byte payload
/// placed at `offset` within segment `segment_idx`.
#[derive(Debug, Clone)]
pub struct DataRecord {
    pub segment_idx: u16,
    pub offset: u32,
    pub bytes: Vec<u8>,
}

/// One fixup (decoded from a FIXUPP record). The semantic mapping to COFF
/// `Reloc` happens in [`to_coff_object`].
///
/// Fields:
/// - `is_self_relative`: true ⇒ relative (PC-relative) fixup; false ⇒
///   segment-relative (absolute).
/// - `location`: location-type code (LOC field; identifies how many bytes
///   the fixup patches and how they're laid out).
/// - `data_segment_idx`: which segment's data the fixup writes into
///   (1-based).
/// - `data_offset`: byte offset within that segment.
/// - `frame_method`: F0-F5 (encoded as 0-5 in the high nibble of the
///   fix-data byte).
/// - `frame_datum`: associated datum (segment / group / external index).
/// - `target_method`: T0-T6 (encoded as 0-6 in the low nibble of the
///   fix-data byte; methods T4-T6 omit the displacement field).
/// - `target_datum`: associated datum (segment / group / external index).
/// - `target_disp`: displacement added to the target (0 for T4-T6).
#[derive(Debug, Clone)]
pub struct Fixup {
    pub is_self_relative: bool,
    pub location: u8,
    pub data_segment_idx: u16,
    pub data_offset: u32,
    pub frame_method: u8,
    pub frame_datum: u16,
    pub target_method: u8,
    pub target_datum: u16,
    pub target_disp: u32,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OmfError {
    Truncated,
    /// A length-prefixed name extended past the record body.
    BadNameLength,
    /// An LNAMES index landed outside the populated table. Carries the
    /// offending index for diagnostics.
    BadLnameIndex(u16),
    /// A record header declared a length the underlying buffer can't satisfy.
    BadRecordLength {
        record_type: u8,
        declared: u16,
    },
    /// A USE16 segment was encountered (16-bit real-mode DOS OMF).
    Use16NotSupported,
    /// An unsupported FIXUPP location code (e.g. 16-bit pointer encodings).
    UnsupportedFixup {
        location: u8,
        record_offset: u32,
    },
    /// A FIXUPP referenced a segment / external index that wasn't defined
    /// before the fixup record (illegal in OMF — every reference must
    /// follow a definition).
    BadFixupIndex {
        which: &'static str,
        index: u16,
    },
    /// Translation produced a relocation whose location-write would land
    /// outside its data segment's bounds (corrupt LEDATA / FIXUPP pair).
    FixupOutOfRange {
        segment_idx: u16,
        offset: u32,
    },
    /// `to_coff_object` could not match a segment name to a canonical COFF
    /// section kind AND failed the Custom fallback (e.g. empty name).
    BadSegmentName(String),
}

impl fmt::Display for OmfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OmfError::Truncated => write!(f, "OMF stream truncated"),
            OmfError::BadNameLength => write!(f, "OMF name length runs past record"),
            OmfError::BadLnameIndex(i) => write!(f, "OMF LNAMES index {i} out of range"),
            OmfError::BadRecordLength {
                record_type,
                declared,
            } => write!(
                f,
                "OMF record 0x{record_type:02X} declared length {declared} > buffer"
            ),
            OmfError::Use16NotSupported => write!(
                f,
                "OMF segment is USE16 (16-bit real-mode); mdlink supports USE32 (Win32) only"
            ),
            OmfError::UnsupportedFixup {
                location,
                record_offset,
            } => write!(
                f,
                "OMF FIXUPP location code {location} at record offset 0x{record_offset:08X} \
                 is not supported (only OFFSET32 / OFFSET16 / LOWBYTE forms are decoded)"
            ),
            OmfError::BadFixupIndex { which, index } => {
                write!(f, "OMF FIXUPP references undefined {which} index {index}")
            }
            OmfError::FixupOutOfRange {
                segment_idx,
                offset,
            } => write!(
                f,
                "OMF FIXUPP writes past segment {segment_idx} bounds at offset 0x{offset:08X}"
            ),
            OmfError::BadSegmentName(n) => {
                write!(f, "OMF segment name '{n}' has no canonical COFF mapping")
            }
        }
    }
}

impl std::error::Error for OmfError {}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Decode `bytes` as an OMF object module. Stops at the first MODEND;
/// anything after MODEND is ignored (some Borland tools concatenate
/// multiple modules in `.lib` archives, which the parser does not handle —
/// that's `src/link/archive.rs`'s S1c.7 job).
pub fn read(bytes: &[u8]) -> Result<OmfImage, OmfError> {
    let mut img = OmfImage {
        // LNAMES is 1-indexed; reserve slot 0 with an empty string so
        // `lnames[0]` is a valid (sentinel) lookup.
        lnames: vec![String::new()],
        ..OmfImage::default()
    };
    let mut cursor = 0usize;
    while cursor + 3 <= bytes.len() {
        let rec_type = bytes[cursor];
        let rec_len = u16::from_le_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
        let body_start = cursor + 3;
        let body_end = body_start + rec_len.saturating_sub(1); // exclude checksum
        let rec_end = body_start + rec_len; // includes checksum
        if rec_len == 0 || rec_end > bytes.len() {
            return Err(OmfError::BadRecordLength {
                record_type: rec_type,
                declared: rec_len as u16,
            });
        }
        let body = &bytes[body_start..body_end];

        match rec_type {
            0x80 | 0x82 => {
                // THEADR / LHEADR — translator-supplied source file name.
                // Body is a single Pascal string.
                if let Ok((name, _)) = read_pascal_string(body) {
                    img.source = name;
                }
            }
            0x88 => {
                // COMENT — comment record. We deliberately ignore every
                // class (no Borland-specific link directive is needed for
                // S1c.6's basic linking).
            }
            0x96 | 0x97 => decode_lnames(body, &mut img.lnames)?,
            0x98 | 0x99 => {
                let seg = decode_segdef(rec_type, body)?;
                img.segments.push(seg);
            }
            0x9A | 0x9B => {
                let grp = decode_grpdef(body)?;
                img.groups.push(grp);
            }
            0x90 | 0x91 | 0xB6 | 0xB7 => {
                decode_pubdef(rec_type, body, &mut img.pubdefs)?;
            }
            0x8C | 0xB4 => {
                decode_extdef(body, &mut img.extdefs)?;
            }
            0xB0 | 0xB8 => {
                decode_comdef(body, &mut img.comdefs)?;
            }
            0xC2 | 0xC3 => {
                let cd = decode_comdat(rec_type, body, &img.lnames)?;
                img.comdats.push(cd);
            }
            0xA0 | 0xA1 => {
                let dr = decode_ledata(rec_type, body, &mut img.segments)?;
                img.data_records.push(dr);
            }
            0xA2 | 0xA3 => {
                let dr = decode_lidata(rec_type, body, &mut img.segments)?;
                img.data_records.push(dr);
            }
            0x9C | 0x9D => {
                // FIXUPP needs to read the image (for the data-record /
                // comdat context) AND append to img.fixups simultaneously.
                // Take the fixups vec out, decode into it, then put it back.
                let mut sink = std::mem::take(&mut img.fixups);
                decode_fixupp_into(rec_type, body, &img, &mut sink)?;
                img.fixups = sink;
            }
            0x8A | 0x8B => {
                // MODEND — stop the walk.
                break;
            }
            0x94 | 0x95 => {
                // LINNUM — line-number debug; not needed for linking.
            }
            _ => {
                // Unknown record type — skip its body. Borland uses many
                // record types we don't need (BAKPAT, NBKPAT, etc.).
            }
        }
        cursor = rec_end;
    }
    Ok(img)
}

/// Convenience alias matching the legacy walker's `parse` name. Kept so
/// the O13 oracle harness (`tests/oracle_o13_coff_parity.rs`) can switch
/// from `tests::support::omf_walker::parse` to `link::omf::parse` with no
/// other source changes.
pub fn parse(bytes: &[u8]) -> Result<OmfImage, OmfError> {
    read(bytes)
}

// ---------------------------------------------------------------------------
// Per-record decoders
// ---------------------------------------------------------------------------

fn decode_lnames(body: &[u8], lnames: &mut Vec<String>) -> Result<(), OmfError> {
    let mut i = 0usize;
    while i < body.len() {
        let (name, consumed) = read_pascal_string(&body[i..])?;
        lnames.push(name);
        i += consumed;
    }
    Ok(())
}

fn decode_segdef(rec_type: u8, body: &[u8]) -> Result<Segment, OmfError> {
    // SEGDEF body layout (Microsoft OMF spec, simplified for the cases
    // bcc32 actually emits):
    //   [attributes:1]         — ACBP bits (alignment, combination,
    //                            big-flag, protection). When ACBP says
    //                            "absolute segment" (the bottom 3 bits
    //                            equal 0b000_xxxxx i.e. attributes & 0xE0
    //                            == 0), three extra bytes follow:
    //                            FrameNumber (LE u16) + Offset (u8).
    //   [length:2 or 4]        — segment length. 2-byte for 0x98, 4-byte
    //                            for 0x99 (the 32-bit variant). When the
    //                            attribute's "big" bit (bit 1) is set,
    //                            the length field is replaced by zero and
    //                            the actual length is 0x10000 (16-bit) or
    //                            0x100000000 (32-bit, never happens).
    //   [seg_name_idx:idx]     — LNAMES index of the segment name.
    //   [class_name_idx:idx]   — LNAMES index of the class name.
    //   [overlay_name_idx:idx] — LNAMES index of the overlay name
    //                            (Borland always uses 1 → an empty string
    //                            for 32-bit objects). Ignored by us.
    if body.is_empty() {
        return Err(OmfError::Truncated);
    }
    let attributes = body[0];
    let mut p = 1usize;
    // Absolute-segment frame info (3 extra bytes when A bits are 0).
    if (attributes & 0xE0) == 0 {
        if p + 3 > body.len() {
            return Err(OmfError::Truncated);
        }
        p += 3;
    }
    let big_flag = attributes & 0x02 != 0;
    let use32 = attributes & 0x01 != 0;
    let length = if rec_type == 0x99 {
        // 32SEGDEF — 4-byte length.
        if !big_flag {
            if p + 4 > body.len() {
                return Err(OmfError::Truncated);
            }
            let v = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
            p += 4;
            v
        } else {
            // "Big" bit set: declared length zero means 4-GiB segment
            // (never seen in mdbcc-scale code). Still consume the field.
            if p + 4 > body.len() {
                return Err(OmfError::Truncated);
            }
            p += 4;
            0
        }
    } else {
        // 16SEGDEF — 2-byte length.
        if !big_flag {
            if p + 2 > body.len() {
                return Err(OmfError::Truncated);
            }
            let v = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
            p += 2;
            v
        } else {
            if p + 2 > body.len() {
                return Err(OmfError::Truncated);
            }
            p += 2;
            0x10000
        }
    };
    let (name_idx, consumed) = read_index(&body[p..])?;
    p += consumed;
    let (class_idx, consumed) = read_index(&body[p..])?;
    p += consumed;
    // overlay_name_idx — skip
    let (_overlay, consumed) = read_index(&body[p..])?;
    let _ = (p, consumed); // length variable usage to satisfy clippy.
    let data = vec![0u8; length as usize];
    Ok(Segment {
        name_idx,
        class_idx,
        length,
        use32,
        data,
    })
}

fn decode_grpdef(body: &[u8]) -> Result<Group, OmfError> {
    // GRPDEF body layout:
    //   [group_name_idx:idx]
    //   then repeating:
    //     [marker:1]           — always 0xFF (per Microsoft OMF spec)
    //     [segment_idx:idx]    — 1-based SEGDEF index
    if body.is_empty() {
        return Err(OmfError::Truncated);
    }
    let (name_idx, consumed) = read_index(body)?;
    let mut p = consumed;
    let mut seg_indices = Vec::new();
    while p < body.len() {
        // Marker byte (0xFF) — skip.
        p += 1;
        if p >= body.len() {
            break;
        }
        let (seg_idx, consumed) = read_index(&body[p..])?;
        seg_indices.push(seg_idx);
        p += consumed;
    }
    Ok(Group {
        name_idx,
        segment_indices: seg_indices,
    })
}

fn decode_pubdef(rec_type: u8, body: &[u8], pubdefs: &mut Vec<Pubdef>) -> Result<(), OmfError> {
    // PUBDEF body layout:
    //   [base_group_idx:idx]
    //   [base_segment_idx:idx]
    //   [base_frame:2]   — present iff base_segment_idx == 0
    //   then repeating:
    //     [name:pascal]
    //     [offset:2 or 4]   — 4 bytes for 0x91 / 0xB7 (32-bit form)
    //     [type_idx:idx]
    if body.len() < 2 {
        return Err(OmfError::Truncated);
    }
    let (_base_group_idx, consumed1) = read_index(body)?;
    let (base_seg_idx, consumed2) = read_index(&body[consumed1..])?;
    let mut p = consumed1 + consumed2;
    if base_seg_idx == 0 {
        // Absolute symbol — skip 2-byte BaseFrame field.
        if p + 2 > body.len() {
            return Err(OmfError::Truncated);
        }
        p += 2;
    }
    let is_32 = matches!(rec_type, 0x91 | 0xB7);
    while p < body.len() {
        let (name, consumed) = read_pascal_string(&body[p..])?;
        p += consumed;
        let offset = if is_32 {
            if p + 4 > body.len() {
                return Err(OmfError::Truncated);
            }
            let v = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
            p += 4;
            v
        } else {
            if p + 2 > body.len() {
                return Err(OmfError::Truncated);
            }
            let v = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
            p += 2;
            v
        };
        let (type_idx, consumed) = read_index(&body[p..])?;
        p += consumed;
        pubdefs.push(Pubdef {
            name,
            segment_idx: base_seg_idx,
            offset,
            type_idx,
        });
    }
    Ok(())
}

fn decode_extdef(body: &[u8], extdefs: &mut Vec<Extdef>) -> Result<(), OmfError> {
    // EXTDEF body layout — repeating:
    //   [name:pascal]
    //   [type_idx:idx]
    let mut p = 0usize;
    while p < body.len() {
        let (name, consumed) = read_pascal_string(&body[p..])?;
        p += consumed;
        let (type_idx, consumed) = read_index(&body[p..])?;
        p += consumed;
        extdefs.push(Extdef { name, type_idx });
    }
    Ok(())
}

fn decode_comdef(body: &[u8], comdefs: &mut Vec<Comdef>) -> Result<(), OmfError> {
    // COMDEF body layout — repeating:
    //   [name:pascal]
    //   [type_idx:idx]
    //   [data_segment_type:1]
    //   [size or count:variable]
    //
    // For far (0x61): [count:variable] then [size:variable].
    // For near (0x62): [size:variable].
    let mut p = 0usize;
    while p < body.len() {
        let (name, consumed) = read_pascal_string(&body[p..])?;
        p += consumed;
        let (type_idx, consumed) = read_index(&body[p..])?;
        p += consumed;
        if p >= body.len() {
            return Err(OmfError::Truncated);
        }
        let data_seg_type = body[p];
        p += 1;
        let (count, size) = match data_seg_type {
            0x61 => {
                let (count, c1) = read_communal_length(&body[p..])?;
                p += c1;
                let (size, c2) = read_communal_length(&body[p..])?;
                p += c2;
                (count, size)
            }
            0x62 => {
                let (size, c1) = read_communal_length(&body[p..])?;
                p += c1;
                (1, size)
            }
            _ => {
                let (size, c1) = read_communal_length(&body[p..])?;
                p += c1;
                (1, size)
            }
        };
        comdefs.push(Comdef {
            name,
            type_idx,
            count,
            size,
        });
    }
    Ok(())
}

fn decode_comdat(rec_type: u8, body: &[u8], lnames: &[String]) -> Result<Comdat, OmfError> {
    if body.len() < 5 {
        return Err(OmfError::Truncated);
    }
    let _flags = body[0];
    let attributes = body[1];
    let _align = body[2];
    let mut p = 3usize;
    let is_32 = rec_type == 0xC3;
    let offset = if is_32 {
        if p + 4 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
        p += 4;
        v
    } else {
        if p + 2 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
        p += 2;
        v
    };
    let (_type_idx, consumed) = read_index(&body[p..])?;
    p += consumed;
    let alloc = attributes & 0x0F;
    let mut segment_idx = 0u16;
    if alloc == 0 {
        let (_group, c1) = read_index(&body[p..])?;
        p += c1;
        let (seg, c2) = read_index(&body[p..])?;
        p += c2;
        segment_idx = seg;
    }
    let (name_idx, consumed) = read_index(&body[p..])?;
    let _ = consumed;
    let name = lnames
        .get(name_idx as usize)
        .cloned()
        .ok_or(OmfError::BadLnameIndex(name_idx))?;
    Ok(Comdat {
        name,
        segment_idx,
        offset,
    })
}

/// Decode an LEDATA record. Writes the payload bytes into the appropriate
/// segment's data buffer at the given offset; returns a [`DataRecord`]
/// summarising the operation (the data is owned by the buffer; the
/// DataRecord is for round-trip / debugging visibility).
fn decode_ledata(
    rec_type: u8,
    body: &[u8],
    segments: &mut [Segment],
) -> Result<DataRecord, OmfError> {
    // LEDATA body layout:
    //   [segment_idx:idx]
    //   [data_offset:2 or 4]   — 4 bytes for 0xA1 (32-bit form)
    //   [bytes:remaining]
    let (segment_idx, consumed) = read_index(body)?;
    let mut p = consumed;
    let is_32 = rec_type == 0xA1;
    let offset = if is_32 {
        if p + 4 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
        p += 4;
        v
    } else {
        if p + 2 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
        p += 2;
        v
    };
    let payload = body[p..].to_vec();

    // Write the payload into the appropriate segment's data buffer. The
    // segment must exist (1-based index); the payload must fit.
    let seg_ix = segment_idx as usize;
    if seg_ix == 0 || seg_ix > segments.len() {
        return Err(OmfError::BadFixupIndex {
            which: "segment",
            index: segment_idx,
        });
    }
    let seg = &mut segments[seg_ix - 1];
    let end = offset as usize + payload.len();
    if end > seg.data.len() {
        // Grow the segment to fit (bcc32 sometimes emits LEDATA past the
        // SEGDEF-declared length when SEGDEF lacked the big-flag).
        seg.data.resize(end, 0);
    }
    seg.data[offset as usize..end].copy_from_slice(&payload);

    Ok(DataRecord {
        segment_idx,
        offset,
        bytes: payload,
    })
}

/// Decode an LIDATA record. LIDATA is RLE-style iterated data: a sequence
/// of `(repeat_count, block_count, block_contents)` triples nested arbi-
/// trarily deep. We flatten the iteration in-memory then write the flat
/// payload into the segment's data buffer, mirroring LEDATA.
fn decode_lidata(
    rec_type: u8,
    body: &[u8],
    segments: &mut [Segment],
) -> Result<DataRecord, OmfError> {
    // LIDATA body layout:
    //   [segment_idx:idx]
    //   [data_offset:2 or 4]   — 4 bytes for 0xA3 (32-bit form)
    //   [iterated_data_block ...]
    //
    // Each iterated_data_block (recursive):
    //   [repeat_count:2 or 4]  — 4 bytes for the 32-bit variant
    //   [block_count:2]
    //   if block_count == 0:
    //     [content_len:1]
    //     [content:content_len]
    //   else:
    //     [iterated_data_block * block_count]
    let (segment_idx, consumed) = read_index(body)?;
    let mut p = consumed;
    let is_32 = rec_type == 0xA3;
    let offset = if is_32 {
        if p + 4 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
        p += 4;
        v
    } else {
        if p + 2 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
        p += 2;
        v
    };

    let mut payload: Vec<u8> = Vec::new();
    while p < body.len() {
        expand_iterated_block(body, &mut p, is_32, &mut payload)?;
    }

    let seg_ix = segment_idx as usize;
    if seg_ix == 0 || seg_ix > segments.len() {
        return Err(OmfError::BadFixupIndex {
            which: "segment",
            index: segment_idx,
        });
    }
    let seg = &mut segments[seg_ix - 1];
    let end = offset as usize + payload.len();
    if end > seg.data.len() {
        seg.data.resize(end, 0);
    }
    seg.data[offset as usize..end].copy_from_slice(&payload);

    Ok(DataRecord {
        segment_idx,
        offset,
        bytes: payload,
    })
}

/// Expand one iterated-data block recursively into `out`.
fn expand_iterated_block(
    body: &[u8],
    p: &mut usize,
    is_32: bool,
    out: &mut Vec<u8>,
) -> Result<(), OmfError> {
    let repeat_count = if is_32 {
        if *p + 4 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u32::from_le_bytes([body[*p], body[*p + 1], body[*p + 2], body[*p + 3]]);
        *p += 4;
        v
    } else {
        if *p + 2 > body.len() {
            return Err(OmfError::Truncated);
        }
        let v = u16::from_le_bytes([body[*p], body[*p + 1]]) as u32;
        *p += 2;
        v
    };
    if *p + 2 > body.len() {
        return Err(OmfError::Truncated);
    }
    let block_count = u16::from_le_bytes([body[*p], body[*p + 1]]) as usize;
    *p += 2;
    if block_count == 0 {
        // Leaf: content_len byte, then that many content bytes.
        if *p >= body.len() {
            return Err(OmfError::Truncated);
        }
        let content_len = body[*p] as usize;
        *p += 1;
        if *p + content_len > body.len() {
            return Err(OmfError::Truncated);
        }
        let content = &body[*p..*p + content_len];
        *p += content_len;
        for _ in 0..repeat_count {
            out.extend_from_slice(content);
        }
    } else {
        // Recursive: expand each inner block, then repeat the whole.
        let inner_start = out.len();
        for _ in 0..block_count {
            expand_iterated_block(body, p, is_32, out)?;
        }
        let inner_len = out.len() - inner_start;
        // Repeat the whole inner content `repeat_count - 1` more times
        // (we already emitted it once).
        for _ in 1..repeat_count {
            let inner = out[inner_start..inner_start + inner_len].to_vec();
            out.extend_from_slice(&inner);
        }
    }
    Ok(())
}

/// Decode a FIXUPP record into the supplied sink. Each FIXUPP record can
/// contain multiple fixup subrecords AND/OR thread subrecords. Threads
/// (subrecord with high bit clear in the leading byte) provide reusable
/// frame / target references; we decode them into a small per-record
/// scratch table but do NOT carry them across records (Borland's
/// `tlink32` resets the thread table at each FIXUPP — we mirror that
/// conservative behaviour).
fn decode_fixupp_into(
    rec_type: u8,
    body: &[u8],
    img: &OmfImage,
    fixups: &mut Vec<Fixup>,
) -> Result<(), OmfError> {
    // Per-record thread state. F0..F3 frame threads, T0..T3 target
    // threads. Each thread records (method, datum).
    let mut frame_threads: [Option<(u8, u16)>; 4] = [None; 4];
    let mut target_threads: [Option<(u8, u16)>; 4] = [None; 4];

    let is_32 = rec_type == 0x9D;

    let mut p = 0usize;
    while p < body.len() {
        let lead = body[p];
        if lead & 0x80 == 0 {
            // THREAD subrecord:
            //   bit 7 = 0
            //   bit 6 = D (1 = frame thread, 0 = target thread)
            //   bits 5..3 = method (0..3 for threads — F0-F3 / T0-T3)
            //   bits 1..0 = thread number (0..3)
            // Followed by index iff method <= 2 (F0/F1/F2 carry segment/
            // group/external index; F3/F4/F5 are self-determined and
            // omit the index). For target threads T0-T3 always carry an
            // index (T0/T1/T2/T3 specify segment/group/external/frame).
            let is_frame = (lead & 0x40) != 0;
            let method = (lead >> 2) & 0x07;
            let thread_no = (lead & 0x03) as usize;
            p += 1;
            // Frame threads with method >= 4 (F4 = target-determines,
            // F5 = "no frame") have no datum; target threads always do.
            let needs_datum = if is_frame { method <= 3 } else { true };
            let datum = if needs_datum {
                let (v, c) = read_index(&body[p..])?;
                p += c;
                v
            } else {
                0
            };
            if is_frame {
                frame_threads[thread_no] = Some((method, datum));
            } else {
                target_threads[thread_no] = Some((method, datum));
            }
            continue;
        }
        // FIXUP subrecord. Layout:
        //   [locat:2 BIG-endian]  — bit 15 = 1 (set by `lead & 0x80`),
        //                           bit 14 = M (self-relative if 0;
        //                                       segment-relative if 1),
        //                           bits 13..10 = location code (LOC),
        //                           bits 9..0 = data record offset.
        //   [fix-data:1]
        //                           bit 7 = F (1 = frame uses thread)
        //                           bits 6..4 = frame (method or thread #)
        //                           bit 3 = T (1 = target uses thread)
        //                           bit 2 = P (1 = no target displacement)
        //                           bits 1..0 = target (method or thread #)
        //   [frame_datum:idx]      — present iff F == 0 and method <= 2
        //   [target_datum:idx]     — present iff T == 0
        //   [target_disp:2 or 4]   — present iff P == 0 (4 bytes for 0x9D)
        if p + 1 >= body.len() {
            return Err(OmfError::Truncated);
        }
        let locat = ((body[p] as u16) << 8) | body[p + 1] as u16;
        p += 2;
        let is_segment_relative = (locat & 0x4000) != 0;
        let location = ((locat >> 10) & 0x0F) as u8;
        let data_offset = (locat & 0x03FF) as u32;
        if p >= body.len() {
            return Err(OmfError::Truncated);
        }
        let fix_data = body[p];
        p += 1;
        let f_bit = (fix_data & 0x80) != 0;
        let frame_field = (fix_data >> 4) & 0x07;
        let t_bit = (fix_data & 0x08) != 0;
        let p_bit = (fix_data & 0x04) != 0;
        let target_field = fix_data & 0x03;

        // Resolve frame method + datum.
        let (frame_method, frame_datum) = if f_bit {
            // Thread reference.
            match frame_threads[frame_field as usize & 0x03] {
                Some(v) => v,
                None => (frame_field, 0),
            }
        } else {
            // Explicit frame.
            let method = frame_field;
            let datum = if method <= 2 {
                let (v, c) = read_index(&body[p..])?;
                p += c;
                v
            } else {
                0
            };
            (method, datum)
        };

        // Resolve target method + datum.
        let (target_method_raw, target_datum) = if t_bit {
            // Thread reference. Borland's encoding: P==1 implies "target
            // method is thread # XX, no displacement"; P==0 means same
            // thread # but with the original method's "with-disp" mode.
            // Either way the target threads carry methods 0..3 (T0..T3).
            match target_threads[target_field as usize & 0x03] {
                Some(v) => v,
                None => (target_field, 0),
            }
        } else {
            // Explicit target.
            let method = target_field;
            let (datum, c) = read_index(&body[p..])?;
            p += c;
            (method, datum)
        };
        // The P bit distinguishes "method with displacement" (P=0, methods
        // T0/T1/T2/T3) from "method without displacement" (P=1, methods
        // T4/T5/T6). The low two bits of method tell us which target-
        // class (segment / group / external / frame) we're addressing;
        // the displacement form just adds an addend.
        let target_method = if p_bit {
            target_method_raw | 0x04
        } else {
            target_method_raw
        };

        let target_disp = if !p_bit {
            if is_32 {
                if p + 4 > body.len() {
                    return Err(OmfError::Truncated);
                }
                let v = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
                p += 4;
                v
            } else {
                if p + 2 > body.len() {
                    return Err(OmfError::Truncated);
                }
                let v = u16::from_le_bytes([body[p], body[p + 1]]) as u32;
                p += 2;
                v
            }
        } else {
            0
        };

        // The fixup applies to whichever LEDATA / LIDATA / COMDAT most
        // recently appeared. We track this via `img.data_records.last()`
        // — every FIXUPP must follow a data record that establishes the
        // "current segment context".
        let (data_segment_idx, base_offset) = if let Some(last) = img.data_records.last() {
            (last.segment_idx, last.offset)
        } else if let Some(last) = img.comdats.last() {
            (last.segment_idx, last.offset)
        } else {
            return Err(OmfError::BadFixupIndex {
                which: "data-record",
                index: 0,
            });
        };

        fixups.push(Fixup {
            is_self_relative: !is_segment_relative,
            location,
            data_segment_idx,
            data_offset: base_offset + data_offset,
            frame_method,
            frame_datum,
            target_method,
            target_datum,
            target_disp,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OMF → COFF translation
// ---------------------------------------------------------------------------

/// Translate a decoded [`OmfImage`] into a [`coff::Object`] suitable for
/// feeding to [`crate::link::pe_writer::write_pe_from_objects`].
///
/// Mapping rules (HLD §3):
/// - Each OMF segment becomes a COFF section. `_TEXT` / class `CODE` →
///   `.text`; `_DATA` / class `DATA` → `.data`; `_BSS` / class `BSS` →
///   `.bss`; `_RDATA` / `_CONST` / class `CONST` → `.rdata`. Anything
///   else → `SectionName::Custom(raw_name)`.
/// - PUBDEF entries become defined EXTERNAL symbols (`SectionRef::Section(n)`
///   with `value = pubdef.offset`).
/// - EXTDEF entries become undefined EXTERNAL symbols.
/// - COMDEF entries become defined section symbols (synthesised `.bss`-like
///   COMDAT sections with the supplied size).
/// - FIXUPP records become COFF relocations against either a defined
///   section symbol (segment-relative target) or an undefined external
///   (extdef target). The COFF reloc kind is picked based on the FIXUPP
///   location code and the segment-vs-self-relative flag.
///
/// The returned Object's `machine` is set to `coff::Machine::I386` because
/// bcc32 emits 32-bit OMF (the OMF reader does not synthesise 64-bit code
/// from 32-bit input). mdlink's pe_writer rejects non-AMD64 inputs today;
/// the actual PE-execution path is a forward-compat seam (S1c.7+ / 32-bit
/// PE writer work).
pub fn to_coff_object(img: &OmfImage) -> Result<coff::Object, OmfError> {
    let mut obj = coff::Object {
        machine: coff::Machine::I386,
        ..coff::Object::default()
    };

    // -- Sections ----------------------------------------------------------
    //
    // OMF segment N (1-based) maps to COFF section N (1-based). We allocate
    // them in the same order so the SectionRef::Section(n) values that
    // pubdef.segment_idx becomes still point at the right place.
    let mut section_kinds: Vec<SectionKind> = Vec::with_capacity(img.segments.len());
    for seg in &img.segments {
        let seg_name = seg.name(&img.lnames).unwrap_or("");
        let seg_class = seg.class(&img.lnames).unwrap_or("");
        let kind = classify_segment(seg_name, seg_class);
        section_kinds.push(kind);
        let section = match kind {
            SectionKind::Text => {
                let mut s = Section::text();
                s.data = seg.data.clone();
                s
            }
            SectionKind::Data => {
                let mut s = Section::data();
                s.data = seg.data.clone();
                s
            }
            SectionKind::Bss => {
                // BSS — no data, just a size. Use the SEGDEF-declared length
                // (some bcc32 outputs LEDATA into _BSS for tentative-defs
                // with init data, in which case we treat them as .data
                // instead — but the default and overwhelmingly common case
                // is "BSS is zero-init storage of declared length").
                if seg.data.iter().all(|&b| b == 0) {
                    Section::bss(seg.length)
                } else {
                    // Promote to .data: this segment has init bytes.
                    let mut s = Section::data();
                    s.data = seg.data.clone();
                    s
                }
            }
            SectionKind::Rdata => {
                let mut s = Section::rdata();
                s.data = seg.data.clone();
                s
            }
            SectionKind::Other => {
                let name = if seg_name.is_empty() {
                    format!(".unknown_{}", obj.sections.len() + 1)
                } else {
                    seg_name.to_string()
                };
                // Other sections become a generic Custom section. We use a
                // Data-like characteristics value (read/write, initialised
                // data) so the linker is permissive — bcc32 emits e.g.
                // `_INIT_` and `_FINI_` sections for static-ctor ordering
                // that we want pulled through as-is.
                Section {
                    name: SectionName::Custom(name),
                    data: seg.data.clone(),
                    bss_size: 0,
                    relocs: Vec::new(),
                    characteristics: 0x40_00_00_40, // READ | INITIALIZED_DATA
                    comdat: None,
                }
            }
        };
        obj.sections.push(section);
    }

    // -- Section symbols --------------------------------------------------
    //
    // Per the COFF spec each section gets a STATIC symbol with the section
    // name and an aux SectionDef record. We emit these so downstream
    // tooling that walks the symbol table (dumpbin, lld-link) sees a sane
    // table. They also serve as the "owning symbol" for sections that have
    // no PUBDEF — the linker's section-defined-symbol lookup needs at
    // least one symbol per section to map RVAs through.
    for (i, sec) in obj.sections.iter().enumerate() {
        let raw_name = sec.name.render();
        let name = SymName::from_str(&raw_name, &mut obj.strtab);
        obj.symbols.push(Symbol {
            name,
            value: 0,
            section: SectionRef::Section((i + 1) as u16),
            kind: SymKind::Notype,
            storage: StorageClass::Static,
            aux: Vec::new(),
        });
        obj.symbol_source_locs.push(None);
    }

    // -- Pubdefs -> defined externals -------------------------------------
    for pd in &img.pubdefs {
        let section = if pd.segment_idx == 0 {
            SectionRef::Absolute
        } else if pd.segment_idx as usize > obj.sections.len() {
            // Out-of-range — synthesise undefined as a best-effort.
            SectionRef::Undefined
        } else {
            SectionRef::Section(pd.segment_idx)
        };
        let name = SymName::from_str(&pd.name, &mut obj.strtab);
        // Heuristic: treat PUBDEFs whose target section is .text as
        // functions. This affects the COFF Type field; the linker doesn't
        // care, but dumpbin and downstream tooling do.
        let kind = if pd.segment_idx > 0
            && pd.segment_idx as usize <= section_kinds.len()
            && section_kinds[pd.segment_idx as usize - 1] == SectionKind::Text
        {
            SymKind::Function
        } else {
            SymKind::Notype
        };
        obj.symbols.push(Symbol {
            name,
            value: pd.offset,
            section,
            kind,
            storage: StorageClass::External,
            aux: Vec::new(),
        });
        obj.symbol_source_locs.push(None);
    }

    // -- Extdefs -> undefined externals -----------------------------------
    //
    // The EXTDEF index within the OMF is significant (FIXUPP target_method
    // T2 / T6 references externals by 1-based EXTDEF index). We record
    // each EXTDEF's resulting symbol index here so the FIXUPP→Reloc
    // translation can look them up.
    let extdef_sym_base = obj.symbols.len();
    for ed in &img.extdefs {
        let name = SymName::from_str(&ed.name, &mut obj.strtab);
        obj.symbols.push(Symbol {
            name,
            value: 0,
            section: SectionRef::Undefined,
            kind: SymKind::Notype,
            storage: StorageClass::External,
            aux: Vec::new(),
        });
        obj.symbol_source_locs.push(None);
    }

    // -- Comdefs ----------------------------------------------------------
    //
    // COMDEF is "weak BSS": a name + zero-init size. We synthesise a
    // .bss-like COMDAT section per COMDEF and an EXTERNAL symbol at
    // offset 0. The linker dedupes COMDATs by name.
    for cd in &img.comdefs {
        let size = cd.count.saturating_mul(cd.size).max(1);
        let section = Section {
            name: SectionName::Custom(format!(".bss${}", cd.name)),
            data: Vec::new(),
            bss_size: size,
            relocs: Vec::new(),
            characteristics: 0xC050_0080, // BSS | READ | WRITE | ALIGN_16
            comdat: None,
        };
        let sec_ix = (obj.sections.len() + 1) as u16;
        obj.sections.push(section);
        let name = SymName::from_str(&cd.name, &mut obj.strtab);
        obj.symbols.push(Symbol {
            name,
            value: 0,
            section: SectionRef::Section(sec_ix),
            kind: SymKind::Notype,
            storage: StorageClass::External,
            aux: Vec::new(),
        });
        obj.symbol_source_locs.push(None);
    }

    // -- Fixups -> relocs --------------------------------------------------
    //
    // Walk each fixup, compute the COFF reloc, and attach to the data-
    // segment's section. The reloc's `symbol` is a 0-based index into the
    // obj.symbols list (the COFF encoder maps to the on-disk aux-aware
    // index automatically).
    //
    // Target methods (low bits of target_method, after the P-bit twist):
    //   T0 (0): segment-relative. target_datum = 1-based SEGDEF index.
    //   T1 (1): group-relative.   target_datum = 1-based GRPDEF index.
    //   T2 (2): external.         target_datum = 1-based EXTDEF index.
    //   T4 (4): same as T0 but no displacement.
    //   T5 (5): same as T1 but no displacement.
    //   T6 (6): same as T2 but no displacement.
    //
    // We compute the symbol index:
    //   - T0/T4: the section's owning STATIC symbol (the per-section symbol
    //     emitted above; index = target_datum - 1 because we emit section
    //     symbols first, in order).
    //   - T1/T5: the first segment of the group (heuristic — see GRPDEF
    //     notes).
    //   - T2/T6: extdef_sym_base + target_datum - 1.
    //
    // The location code drives the COFF reloc kind:
    //   0 (LOW_BYTE):       — 1-byte; not supported (Borland never emits).
    //   1 (OFFSET16):       — 2-byte segment offset. Map to Addr32 (lossy);
    //                         most callers don't hit this on USE32 input.
    //   2 (SEGMENT16):      — 2-byte segment number. Not supported in PE.
    //   3 (POINTER32):      — 4-byte segment:offset (16:16). Not supported.
    //   4 (HIGH_BYTE):      — 1-byte high byte. Not supported.
    //   5 (LOADER_OFFSET16):— 2-byte loader-resolved offset. Not supported.
    //   9 (OFFSET32):       — 4-byte offset. Map to Rel32 (self-relative)
    //                         or Addr32 (segment-relative).
    //   11 (POINTER48):     — 6-byte 16:32 far pointer. Not supported.
    //   13 (LOADER_OFFSET32):— 4-byte loader-resolved offset. Map as OFFSET32.
    //
    // Per HLD §3.2 we narrow the supported set to OFFSET32 (the only one
    // bcc32 emits for 32-bit code). OFFSET16 is decoded as Addr32 with a
    // warning-via-Internal-error for now (no bcc32 test fixture exercises
    // it).
    for fx in &img.fixups {
        let data_sec_ix = fx.data_segment_idx as usize;
        if data_sec_ix == 0 || data_sec_ix > obj.sections.len() {
            return Err(OmfError::BadFixupIndex {
                which: "data-segment",
                index: fx.data_segment_idx,
            });
        }
        let kind = match (fx.location, fx.is_self_relative) {
            (9, true) | (13, true) => RelocKind::Rel32,
            (9, false) | (13, false) => RelocKind::Addr32,
            // Low-byte / 16-bit / 48-bit forms — not in scope for 32-bit
            // Win32 OMF (every fixup bcc32 emits for `.text` is OFFSET32
            // self-relative; `.data` references to function addresses use
            // OFFSET32 segment-relative). If we hit any of these we fail
            // loud rather than silently mis-encoding.
            _ => {
                return Err(OmfError::UnsupportedFixup {
                    location: fx.location,
                    record_offset: fx.data_offset,
                });
            }
        };

        // Resolve target → symbol index.
        let symbol = match fx.target_method & 0x07 {
            0 | 4 => {
                // Segment-relative. target_datum is 1-based SEGDEF index;
                // the section symbol for that segment is at index
                // (target_datum - 1) in obj.symbols (we emitted them in
                // order, first thing after Object init).
                if fx.target_datum == 0 || fx.target_datum as usize > section_kinds.len() {
                    return Err(OmfError::BadFixupIndex {
                        which: "segment-target",
                        index: fx.target_datum,
                    });
                }
                (fx.target_datum - 1) as u32
            }
            1 | 5 => {
                // Group-relative. Heuristic: pick the group's first
                // segment as the symbol. Borland's DGROUP is typically
                // _DATA + _BSS + _CONST; the first one is _DATA whose
                // section symbol is at obj.symbols[seg_ix - 1].
                let grp_ix = fx.target_datum as usize;
                if grp_ix == 0 || grp_ix > img.groups.len() {
                    return Err(OmfError::BadFixupIndex {
                        which: "group-target",
                        index: fx.target_datum,
                    });
                }
                let first_seg = img.groups[grp_ix - 1]
                    .segment_indices
                    .first()
                    .copied()
                    .ok_or(OmfError::BadFixupIndex {
                        which: "empty-group",
                        index: fx.target_datum,
                    })?;
                if first_seg == 0 || first_seg as usize > section_kinds.len() {
                    return Err(OmfError::BadFixupIndex {
                        which: "group-first-segment",
                        index: first_seg,
                    });
                }
                (first_seg - 1) as u32
            }
            2 | 6 => {
                // External-relative. target_datum is 1-based EXTDEF index.
                if fx.target_datum == 0 || fx.target_datum as usize > img.extdefs.len() {
                    return Err(OmfError::BadFixupIndex {
                        which: "external-target",
                        index: fx.target_datum,
                    });
                }
                (extdef_sym_base + (fx.target_datum as usize - 1)) as u32
            }
            _ => {
                return Err(OmfError::BadFixupIndex {
                    which: "target-method",
                    index: fx.target_method as u16,
                });
            }
        };

        // Attach the reloc to the data-segment's section. The fixup
        // offset is data_offset (already adjusted by the LEDATA base).
        let sec = &mut obj.sections[data_sec_ix - 1];
        let off_end = fx.data_offset as usize
            + match kind {
                RelocKind::Addr64 => 8,
                _ => 4,
            };
        if !sec.data.is_empty() && off_end > sec.data.len() {
            return Err(OmfError::FixupOutOfRange {
                segment_idx: fx.data_segment_idx,
                offset: fx.data_offset,
            });
        }
        sec.relocs.push(coff::Reloc {
            offset: fx.data_offset,
            symbol,
            kind,
        });

        // OMF FIXUPP for OFFSET32 with target_disp non-zero stores the
        // displacement bytes into the data buffer at the fixup site. The
        // linker reads these bytes back when computing the final value;
        // pre-baking the displacement is OMF's convention. If we left them
        // zero, the linker would patch the wrong final value.
        if fx.target_disp != 0 && off_end <= sec.data.len() {
            let disp = fx.target_disp.to_le_bytes();
            sec.data[fx.data_offset as usize..off_end].copy_from_slice(&disp);
        }
    }

    Ok(obj)
}

/// One-shot helper that combines `read` and `to_coff_object`. The
/// integration test path looks like:
/// ```ignore
/// let coff_obj = omf::read_to_coff(&omf_bytes)?;
/// ```
pub fn read_to_coff(bytes: &[u8]) -> Result<coff::Object, OmfError> {
    let img = read(bytes)?;
    to_coff_object(&img)
}

/// Canonical OMF-segment → COFF-section classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Text,
    Data,
    Bss,
    Rdata,
    Other,
}

fn classify_segment(seg_name: &str, seg_class: &str) -> SectionKind {
    // Name-specific patterns first (more specific), then class fallbacks
    // (less specific). bcc32 uses `_TEXT` (segment name) / `CODE` (class)
    // and friends; other compilers vary, so the class is the second-chance
    // disambiguator.
    match seg_name {
        "_TEXT" => return SectionKind::Text,
        "_DATA" => return SectionKind::Data,
        "_BSS" => return SectionKind::Bss,
        "_RDATA" | "_CONST" => return SectionKind::Rdata,
        _ => {}
    }
    match seg_class {
        "CODE" => SectionKind::Text,
        "CONST" => SectionKind::Rdata,
        "BSS" => SectionKind::Bss,
        "DATA" => SectionKind::Data,
        _ => SectionKind::Other,
    }
}

// ---------------------------------------------------------------------------
// Primitive readers
// ---------------------------------------------------------------------------

/// Pascal string: `[len:1] [bytes:len]`. Returns the parsed name and the
/// number of bytes consumed from `slice`.
fn read_pascal_string(slice: &[u8]) -> Result<(String, usize), OmfError> {
    if slice.is_empty() {
        return Err(OmfError::Truncated);
    }
    let len = slice[0] as usize;
    if 1 + len > slice.len() {
        return Err(OmfError::BadNameLength);
    }
    let bytes = &slice[1..1 + len];
    // Names are ASCII in every BCC-produced OBJ we've seen, but to be
    // safe we lossy-decode.
    let s = String::from_utf8_lossy(bytes).into_owned();
    Ok((s, 1 + len))
}

/// Borland 1-or-2-byte index encoding:
/// - `b < 0x80` ⇒ index = `b`, one byte.
/// - else ⇒ index = `((b & 0x7F) << 8) | next_byte`, two bytes.
fn read_index(slice: &[u8]) -> Result<(u16, usize), OmfError> {
    if slice.is_empty() {
        return Err(OmfError::Truncated);
    }
    let b = slice[0];
    if b < 0x80 {
        Ok((b as u16, 1))
    } else {
        if slice.len() < 2 {
            return Err(OmfError::Truncated);
        }
        let v = (((b & 0x7F) as u16) << 8) | slice[1] as u16;
        Ok((v, 2))
    }
}

/// COMDEF communal-length encoding (Microsoft OMF spec). Distinct from
/// the index encoding above:
/// - `b < 0x80` ⇒ value = `b`, one byte.
/// - `b == 0x81` ⇒ next 2 bytes LE.
/// - `b == 0x84` ⇒ next 3 bytes LE.
/// - `b == 0x88` ⇒ next 4 bytes LE.
fn read_communal_length(slice: &[u8]) -> Result<(u32, usize), OmfError> {
    if slice.is_empty() {
        return Err(OmfError::Truncated);
    }
    let b = slice[0];
    if b < 0x80 {
        return Ok((b as u32, 1));
    }
    match b {
        0x81 => {
            if slice.len() < 3 {
                return Err(OmfError::Truncated);
            }
            Ok((u16::from_le_bytes([slice[1], slice[2]]) as u32, 3))
        }
        0x84 => {
            if slice.len() < 4 {
                return Err(OmfError::Truncated);
            }
            let v = (slice[1] as u32) | ((slice[2] as u32) << 8) | ((slice[3] as u32) << 16);
            Ok((v, 4))
        }
        0x88 => {
            if slice.len() < 5 {
                return Err(OmfError::Truncated);
            }
            Ok((
                u32::from_le_bytes([slice[1], slice[2], slice[3], slice[4]]),
                5,
            ))
        }
        _ => Ok((b as u32, 1)),
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the primitive readers + a tiny synthesized OMF stream.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_index_short_and_long() {
        assert_eq!(read_index(&[0x05]).unwrap(), (5, 1));
        assert_eq!(read_index(&[0x7F, 0xFF]).unwrap(), (0x7F, 1));
        assert_eq!(read_index(&[0x81, 0x23]).unwrap(), (0x123, 2));
        assert_eq!(read_index(&[0xFF, 0xFF]).unwrap(), (0x7FFF, 2));
    }

    #[test]
    fn read_pascal_basic() {
        let (s, n) = read_pascal_string(&[3, b'a', b'b', b'c']).unwrap();
        assert_eq!(s, "abc");
        assert_eq!(n, 4);
        let (s, n) = read_pascal_string(&[0]).unwrap();
        assert_eq!(s, "");
        assert_eq!(n, 1);
    }

    #[test]
    fn read_pascal_truncated() {
        assert_eq!(
            read_pascal_string(&[3, b'a']).unwrap_err(),
            OmfError::BadNameLength,
        );
    }

    #[test]
    fn communal_length_variants() {
        assert_eq!(read_communal_length(&[0x42]).unwrap(), (0x42, 1));
        assert_eq!(
            read_communal_length(&[0x81, 0x34, 0x12]).unwrap(),
            (0x1234, 3),
        );
        assert_eq!(
            read_communal_length(&[0x84, 0x01, 0x02, 0x03]).unwrap(),
            (0x030201, 4),
        );
        assert_eq!(
            read_communal_length(&[0x88, 0x78, 0x56, 0x34, 0x12]).unwrap(),
            (0x12345678, 5),
        );
    }

    fn push_record(stream: &mut Vec<u8>, rec_type: u8, body: &[u8]) {
        stream.push(rec_type);
        let total_len = (body.len() + 1) as u16;
        stream.extend_from_slice(&total_len.to_le_bytes());
        stream.extend_from_slice(body);
        stream.push(0); // checksum — we don't validate
    }

    /// Build a minimal OMF stream: one LNAMES, one SEGDEF, one PUBDEF,
    /// one EXTDEF, then MODEND. Walks cleanly and produces the expected
    /// symbol set — the harness-the-harness check.
    #[test]
    fn minimal_synthesized_walk() {
        let mut stream: Vec<u8> = Vec::new();
        let mut body = Vec::new();
        for s in ["_TEXT", "CODE"] {
            body.push(s.len() as u8);
            body.extend_from_slice(s.as_bytes());
        }
        push_record(&mut stream, 0x96, &body);
        let mut body = Vec::new();
        body.push(0xA9);
        body.extend_from_slice(&15u32.to_le_bytes());
        body.push(1);
        body.push(2);
        body.push(1);
        push_record(&mut stream, 0x99, &body);
        let mut body = Vec::new();
        body.push(0);
        body.push(1);
        body.push(5);
        body.extend_from_slice(b"_main");
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0);
        push_record(&mut stream, 0x91, &body);
        let mut body = Vec::new();
        body.push(5);
        body.extend_from_slice(b"_puts");
        body.push(0);
        push_record(&mut stream, 0x8C, &body);
        push_record(&mut stream, 0x8B, &[0]);

        let img = read(&stream).expect("walk succeeds");
        assert_eq!(
            img.lnames,
            vec!["".to_string(), "_TEXT".to_string(), "CODE".to_string()]
        );
        assert_eq!(img.segments.len(), 1);
        assert_eq!(img.segments[0].length, 15);
        assert_eq!(img.segments[0].name(&img.lnames), Some("_TEXT"));
        assert_eq!(img.segments[0].class(&img.lnames), Some("CODE"));
        assert!(img.segments[0].use32);
        assert_eq!(img.pubdefs.len(), 1);
        assert_eq!(img.pubdefs[0].name, "_main");
        assert_eq!(img.pubdefs[0].offset, 0);
        assert_eq!(img.pubdefs[0].segment_idx, 1);
        assert_eq!(img.extdefs.len(), 1);
        assert_eq!(img.extdefs[0].name, "_puts");
    }

    /// LEDATA writes payload bytes into the segment's data buffer.
    #[test]
    fn ledata_populates_segment() {
        let mut stream: Vec<u8> = Vec::new();
        let mut body = Vec::new();
        for s in ["_TEXT", "CODE"] {
            body.push(s.len() as u8);
            body.extend_from_slice(s.as_bytes());
        }
        push_record(&mut stream, 0x96, &body);
        let mut body = Vec::new();
        body.push(0xA9);
        body.extend_from_slice(&6u32.to_le_bytes());
        body.push(1);
        body.push(2);
        body.push(1);
        push_record(&mut stream, 0x99, &body);
        // LEDATA32: segment 1, offset 0, bytes: mov eax,42; ret
        let mut body = Vec::new();
        body.push(1); // segment idx
        body.extend_from_slice(&0u32.to_le_bytes()); // offset
        body.extend_from_slice(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        push_record(&mut stream, 0xA1, &body);
        push_record(&mut stream, 0x8B, &[0]);

        let img = read(&stream).expect("walk succeeds");
        assert_eq!(img.segments[0].data, [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        assert_eq!(img.data_records.len(), 1);
    }

    /// LIDATA expansion: `repeat=3, block_count=0, content_len=2, content=[0xAA, 0xBB]`
    /// becomes `AA BB AA BB AA BB`.
    #[test]
    fn lidata_repeats_content() {
        let mut stream: Vec<u8> = Vec::new();
        let mut body = Vec::new();
        for s in ["_DATA", "DATA"] {
            body.push(s.len() as u8);
            body.extend_from_slice(s.as_bytes());
        }
        push_record(&mut stream, 0x96, &body);
        let mut body = Vec::new();
        body.push(0xA9);
        body.extend_from_slice(&6u32.to_le_bytes());
        body.push(1);
        body.push(2);
        body.push(1);
        push_record(&mut stream, 0x99, &body);
        // LIDATA32: segment 1, offset 0, iterated block:
        //   repeat=3, block_count=0, content_len=2, content=[AA,BB]
        let mut body = Vec::new();
        body.push(1); // segment idx
        body.extend_from_slice(&0u32.to_le_bytes()); // offset
        body.extend_from_slice(&3u32.to_le_bytes()); // repeat
        body.extend_from_slice(&0u16.to_le_bytes()); // block_count = leaf
        body.push(2); // content_len
        body.extend_from_slice(&[0xAA, 0xBB]);
        push_record(&mut stream, 0xA3, &body);
        push_record(&mut stream, 0x8B, &[0]);

        let img = read(&stream).expect("walk succeeds");
        assert_eq!(img.segments[0].data, [0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB]);
    }

    /// `classify_segment` picks the canonical SectionKind for each Borland
    /// segment name / class pair.
    #[test]
    fn classify_segment_recognises_borland_names() {
        assert_eq!(classify_segment("_TEXT", "CODE"), SectionKind::Text);
        assert_eq!(classify_segment("_DATA", "DATA"), SectionKind::Data);
        assert_eq!(classify_segment("_BSS", "BSS"), SectionKind::Bss);
        assert_eq!(classify_segment("_RDATA", "DATA"), SectionKind::Rdata);
        assert_eq!(classify_segment("_CONST", "CONST"), SectionKind::Rdata);
        // Unknown name with a known class still matches by class.
        assert_eq!(classify_segment("FOO", "CODE"), SectionKind::Text);
        assert_eq!(classify_segment("BAR", "BSS"), SectionKind::Bss);
        // Both unknown → Other.
        assert_eq!(classify_segment("FOO", "BAR"), SectionKind::Other);
    }

    /// to_coff_object: a trivial OMF with one segment + one PUBDEF + one
    /// EXTDEF maps to a coff::Object with the right shape.
    #[test]
    fn to_coff_object_trivial() {
        let mut stream: Vec<u8> = Vec::new();
        let mut body = Vec::new();
        for s in ["_TEXT", "CODE"] {
            body.push(s.len() as u8);
            body.extend_from_slice(s.as_bytes());
        }
        push_record(&mut stream, 0x96, &body);
        let mut body = Vec::new();
        body.push(0xA9);
        body.extend_from_slice(&6u32.to_le_bytes());
        body.push(1);
        body.push(2);
        body.push(1);
        push_record(&mut stream, 0x99, &body);
        let mut body = Vec::new();
        body.push(1); // segment idx
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        push_record(&mut stream, 0xA1, &body);
        let mut body = Vec::new();
        body.push(0);
        body.push(1);
        body.push(5);
        body.extend_from_slice(b"_main");
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0);
        push_record(&mut stream, 0x91, &body);
        let mut body = Vec::new();
        body.push(5);
        body.extend_from_slice(b"_puts");
        body.push(0);
        push_record(&mut stream, 0x8C, &body);
        push_record(&mut stream, 0x8B, &[0]);

        let img = read(&stream).expect("walk succeeds");
        let obj = to_coff_object(&img).expect("translate succeeds");
        // One section (.text) + zero comdef sections.
        assert_eq!(obj.sections.len(), 1);
        assert_eq!(obj.sections[0].name, SectionName::Text);
        assert_eq!(obj.sections[0].data, [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        // Section symbol + PUBDEF + EXTDEF.
        assert_eq!(obj.symbols.len(), 3);
        // Last two should be _main (defined External) and _puts (undefined
        // External).
        let main = &obj.symbols[1];
        assert_eq!(main.storage, StorageClass::External);
        assert!(matches!(main.section, SectionRef::Section(1)));
        let puts = &obj.symbols[2];
        assert_eq!(puts.storage, StorageClass::External);
        assert!(matches!(puts.section, SectionRef::Undefined));
    }
}
