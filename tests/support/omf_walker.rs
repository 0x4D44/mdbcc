//! S1b.6 — minimal OMF (Borland .obj) walker used by the O13 oracle.
//!
//! BCC32 4.52 emits Borland-flavoured OMF object files (NOT COFF; see
//! the long-standing note in `oracle_bcc452.rs`'s `bcc32_compiles_hello_c`
//! test). The O13 oracle bridges the formats: mdbcc emits COFF, bcc32
//! emits OMF, and `tests/oracle_o13_coff_parity.rs` compares the two
//! semantically (symbol set, section sizes, relocation kinds).
//!
//! This module is a stand-alone, std-only OMF reader sized for that
//! comparison. Only the record types we need are decoded; everything
//! else is skipped after reading its (type, length) header. Per
//! HLD §3 / §4.1, we care about:
//!
//! - **LNAMES** (0x96 / 0x97): the table of length-prefixed names
//!   referenced by SEGDEF/PUBDEF/COMDAT segment indices.
//! - **SEGDEF** (0x98 / 0x99): segment definitions with name/class/length.
//! - **PUBDEF / LPUBDEF** (0x90 / 0x91 / 0xB6 / 0xB7): public symbols
//!   with segment index + offset.
//! - **EXTDEF** (0x8C / 0xB4): external (undefined) symbol references.
//! - **COMDEF** (0xB0 / 0xB8): communal (BSS-like) symbols; used by
//!   Borland for typeinfo + template instantiation deduplication.
//! - **COMDAT** (0xC2 / 0xC3): communal data; minimal viable decode is
//!   just to extract the name (selection/attributes are deferred).
//! - **MODEND** (0x8A / 0x8B): end of module — stops the walk.
//!
//! Record framing reminder (Microsoft OMF spec):
//! ```text
//! [type:1] [length:2 LE] [body:length-1] [checksum:1]
//! ```
//! The trailing checksum byte is the 2's-complement sum-mod-256 of every
//! other byte in the record. We do NOT validate it — bcc32's output is
//! authoritative; if it sums wrong we have bigger problems than the
//! walker mis-decoding it.
//!
//! Indices in record bodies use Borland's 1-or-2 byte form:
//! - First byte `b`; if `b < 0x80` the index is `b`.
//! - Else the index is `((b & 0x7F) << 8) | next_byte`. (Big-endian
//!   when the high bit is set.)
//!
//! Names are Pascal strings: `[len:1] [bytes:len]` (no NUL terminator).

#![allow(dead_code)]

use std::fmt;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed OMF image. Field order matches HLD §3 / §4.1 semantic-content
/// vocabulary; the harness compares mdbcc-COFF symbols against these
/// records by mangled name.
#[derive(Debug, Default)]
pub struct OmfImage {
    /// LNAMES table, 1-indexed (entry `[0]` is a sentinel empty name).
    /// Borland references names from SEGDEF/COMDAT by `lnames[idx]`.
    pub lnames: Vec<String>,
    /// SEGDEF records in encounter order.
    pub segments: Vec<Segment>,
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
}

/// One SEGDEF record. `name_idx` / `class_idx` index into `OmfImage.lnames`
/// (1-based). `length` is the SegmentLength field — for 32-bit segments
/// it's a 4-byte LE value (when the 16-bit-segments variant is used, the
/// 2-byte length field is widened by the walker).
#[derive(Debug, Clone)]
pub struct Segment {
    pub name_idx: u16,
    pub class_idx: u16,
    pub length: u32,
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

/// One COMDAT entry — a communal data section. Minimal viable decode for
/// O13: just the symbol name so PUBDEF-like comparisons work.
#[derive(Debug, Clone)]
pub struct Comdat {
    pub name: String,
    pub segment_idx: u16,
    pub offset: u32,
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
        }
    }
}

impl std::error::Error for OmfError {}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Decode `bytes` as an OMF object module. Stops at the first MODEND;
/// anything after MODEND is ignored (some Borland tools concatenate
/// multiple modules in `.lib` archives, which the walker does not handle).
pub fn parse(bytes: &[u8]) -> Result<OmfImage, OmfError> {
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
            0x96 | 0x97 => decode_lnames(body, &mut img.lnames)?,
            0x98 | 0x99 => {
                let seg = decode_segdef(rec_type, body)?;
                img.segments.push(seg);
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
            0x8A | 0x8B => {
                // MODEND — stop the walk.
                break;
            }
            _ => {
                // Unknown record type — skip its body. Borland uses many
                // record types (THEADR, COMENT, LIDATA, LEDATA, FIXUPP,
                // etc.) that we don't need for symbol-set comparison.
            }
        }
        cursor = rec_end;
    }
    Ok(img)
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
    Ok(Segment {
        name_idx,
        class_idx,
        length,
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
    //   [data_segment_type:1]   — 0x61 = far (count+size), 0x62 = near
    //                             (size only).
    //   [size or count:variable] — variable-length unsigned, encoded as:
    //                              < 0x80          ⇒ 1 byte
    //                              == 0x81         ⇒ next 2 bytes LE
    //                              == 0x84         ⇒ next 3 bytes LE
    //                              == 0x88         ⇒ next 4 bytes LE
    //                              (Microsoft OMF "communal-length"
    //                               encoding — not the same as the
    //                               index encoding.)
    //   For far (0x61): [count:variable] then [size:variable].
    //   For near (0x62): [size:variable].
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
                // Far communal: count then size.
                let (count, c1) = read_communal_length(&body[p..])?;
                p += c1;
                let (size, c2) = read_communal_length(&body[p..])?;
                p += c2;
                (count, size)
            }
            0x62 => {
                // Near communal: just size; treat count as 1.
                let (size, c1) = read_communal_length(&body[p..])?;
                p += c1;
                (1, size)
            }
            _ => {
                // Unknown data-segment type. Best-effort: read one length
                // value and move on.
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
    // COMDAT body layout (Microsoft OMF spec, simplified):
    //   [flags:1]            — bit 0 = continuation; bit 1 = iterated.
    //                          mdbcc bcc32 output: zero (one-shot).
    //   [attributes:1]       — selection + allocation (low/high nibbles).
    //   [align:1]            — alignment code (0 = use SEGDEF default).
    //   [enum_data_offset:2 or 4]   — 4 bytes for 0xC3, 2 for 0xC2.
    //   [type_idx:idx]
    //   [public_base:idx-or-group]  — when allocation = "explicit",
    //                                 group + segment indices follow.
    //                                 For Borland output this is the
    //                                 base group index (0) then segment.
    //   [public_name_idx:idx]       — LNAMES index of the COMDAT's
    //                                 public name.
    //   [data:remaining]            — the actual contents (we ignore).
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
    // Allocation type (low nibble of attributes): 0 = explicit (group +
    // segment indices follow), 1 = far code, 2 = far data, 3 = code-32,
    // 4 = data-32. For "explicit" we have to read group + segment.
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
        // Defensive: treat unknown leading byte as 1-byte value. The
        // walker is best-effort for fields it doesn't need to round-trip.
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
        // High bit set ⇒ two-byte big-endian payload.
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

    /// Build a minimal OMF stream: one LNAMES, one SEGDEF, one PUBDEF,
    /// one EXTDEF, then MODEND. Walks cleanly and produces the expected
    /// symbol set — the harness-the-harness check.
    #[test]
    fn minimal_synthesized_walk() {
        let mut stream: Vec<u8> = Vec::new();

        // LNAMES: ["" (sentinel from initial state), "_TEXT", "CODE"]
        // The body holds two Pascal strings: "_TEXT" (5) and "CODE" (4).
        let mut body = Vec::new();
        for s in ["_TEXT", "CODE"] {
            body.push(s.len() as u8);
            body.extend_from_slice(s.as_bytes());
        }
        push_record(&mut stream, 0x96, &body);

        // SEGDEF32 (0x99): attributes = 0xA9 (alignment=5, combination=2,
        //   big=0, P=1 ⇒ USE32). Length = 0x0F (15 bytes). Name idx 1
        //   ("_TEXT"), class idx 2 ("CODE"), overlay idx 1.
        let mut body = Vec::new();
        body.push(0xA9);
        body.extend_from_slice(&15u32.to_le_bytes());
        body.push(1); // name idx
        body.push(2); // class idx
        body.push(1); // overlay idx
        push_record(&mut stream, 0x99, &body);

        // PUBDEF32 (0x91): base group 0, base segment 1, no base frame
        //   (segment != 0), then one name "_main" at offset 0, type 0.
        let mut body = Vec::new();
        body.push(0); // base group idx (0 = none)
        body.push(1); // base segment idx
        body.push(5);
        body.extend_from_slice(b"_main");
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0); // type idx
        push_record(&mut stream, 0x91, &body);

        // EXTDEF (0x8C): one extern "_puts" with type idx 0.
        let mut body = Vec::new();
        body.push(5);
        body.extend_from_slice(b"_puts");
        body.push(0);
        push_record(&mut stream, 0x8C, &body);

        // MODEND32 (0x8B): minimal body — module type only.
        push_record(&mut stream, 0x8B, &[0]);

        let img = parse(&stream).expect("walk succeeds");
        assert_eq!(
            img.lnames,
            vec!["".to_string(), "_TEXT".to_string(), "CODE".to_string()]
        );
        assert_eq!(img.segments.len(), 1);
        assert_eq!(img.segments[0].length, 15);
        assert_eq!(img.segments[0].name(&img.lnames), Some("_TEXT"));
        assert_eq!(img.segments[0].class(&img.lnames), Some("CODE"));
        assert_eq!(img.pubdefs.len(), 1);
        assert_eq!(img.pubdefs[0].name, "_main");
        assert_eq!(img.pubdefs[0].offset, 0);
        assert_eq!(img.pubdefs[0].segment_idx, 1);
        assert_eq!(img.extdefs.len(), 1);
        assert_eq!(img.extdefs[0].name, "_puts");
    }

    fn push_record(stream: &mut Vec<u8>, rec_type: u8, body: &[u8]) {
        stream.push(rec_type);
        let total_len = (body.len() + 1) as u16;
        stream.extend_from_slice(&total_len.to_le_bytes());
        stream.extend_from_slice(body);
        stream.push(0); // checksum — we don't validate
    }
}
