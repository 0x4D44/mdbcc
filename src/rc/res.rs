//! Win32 `.res` binary writer — Phase G2.
//!
//! Format summary (RT_STRING / STRINGTABLE-only in v1):
//!
//! ```text
//!   File   = NullHeader(32) ResRecord*
//!   ResRec = ResHeader Data Pad(to DWORD)
//!   ResHdr = u32 data_size      (size of Data, excl. trailing pad)
//!            u32 header_size    (size of this header — 32 when type/name
//!                                are both u16 ordinals as in RT_STRING)
//!            u16 0xFFFF, u16 type_ordinal   (RT_STRING = 6)
//!            u16 0xFFFF, u16 name_ordinal   (string-table bundle id =
//!                                            (string_id >> 4) + 1)
//!            u32 data_version   (0)
//!            u16 memory_flags   (default 0x1030: MOVEABLE|PURE|DISCARD)
//!            u16 language_id    (primary | (sub << 10); brc32 default
//!                                without LANGUAGE = 0x0809 = en-GB)
//!            u32 version        (0)
//!            u32 characteristics(0)
//! ```
//!
//! STRINGTABLE bundle layout (data section, exactly 16 length-prefixed
//! UTF-16LE strings, in slot order 0..=15 within the bundle):
//!
//! ```text
//!   Bundle = (u16 len_code_units, [u16; len] utf16le)* × 16
//! ```
//!
//! - String IDs map to `bundle_id = (id >> 4) + 1` (Win32
//!   `MAKEINTRESOURCE` convention) and `slot = id & 0xF` within the
//!   bundle. Empty slots are emitted as a single `u16 0`.
//! - `data_size` is the byte length of the bundle data; trailing padding
//!   to the next DWORD boundary is *not* counted but *is* written before
//!   the next record (or EOF).
//!
//! Authoritative oracle: `brc32.exe -r -fo out.res in.rc`. Where this
//! description and brc32 disagree, brc32 wins; see `tests/rc_res.rs` for
//! the byte-exact differential.
//!
//! Extension surface (G4/G5): MENU / ACCELERATORS / DIALOG records all
//! reuse the ResHeader layout above — only the `Data` shape differs.

use super::{
    AcceleratorTable, ControlClass, DialogControl, DialogResource, Language, MenuItem,
    MenuResource, RcUnit, ResId, ResRef, Resource, StringTableEntry, VersionFixedInfo,
    VersionInfoResource, VersionNode,
};

/// RT_MENU resource type ordinal (Win32 `<winuser.h>` `RT_MENU` = 4).
pub(crate) const RT_MENU: u16 = 4;
/// RT_BITMAP resource type ordinal.
pub(crate) const RT_BITMAP: u16 = 2;
/// RT_ICON resource type ordinal.
pub(crate) const RT_ICON: u16 = 3;
/// RT_DIALOG resource type ordinal (Win32 `<winuser.h>` `RT_DIALOG` = 5).
pub(crate) const RT_DIALOG: u16 = 5;
/// RT_STRING resource type ordinal (Win32 `<winuser.h>` `RT_STRING`). Public to
/// `crate::pe` so the `.rsrc` emitter (G3) shares the constant with the `.res`
/// emitter (G2) — one source of truth for the ordinal.
pub(crate) const RT_STRING: u16 = 6;
/// RT_ACCELERATOR resource type ordinal (Win32 `<winuser.h>` `RT_ACCELERATOR` = 9).
pub(crate) const RT_ACCELERATOR: u16 = 9;
/// RT_RCDATA resource type ordinal.
pub(crate) const RT_RCDATA: u16 = 10;
/// RT_GROUP_ICON resource type ordinal.
pub(crate) const RT_GROUP_ICON: u16 = 14;
/// RT_VERSION resource type ordinal.
pub(crate) const RT_VERSION: u16 = 16;

/// Marker used in the `.res` ResHeader to indicate that the following
/// `u16` is an ordinal (rather than the first WCHAR of a name string).
const ORDINAL_MARKER: u16 = 0xFFFF;

/// Default memory flags brc32 emits for STRINGTABLE blocks without
/// explicit modifiers: MOVEABLE | PURE | DISCARDABLE.
const MEM_MOVEABLE: u16 = 0x0010;
const MEM_PURE: u16 = 0x0020;
const MEM_PRELOAD: u16 = 0x0040;
const MEM_DISCARDABLE: u16 = 0x1000;
const DEFAULT_STRINGTABLE_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE | MEM_DISCARDABLE;
/// brc32-observed default for `<id> MENU` blocks (matches STRINGTABLE).
const DEFAULT_MENU_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE | MEM_DISCARDABLE;
/// brc32-observed default for `<id> DIALOG` blocks (matches MENU /
/// STRINGTABLE — verified empirically on brc32 5.40).
const DEFAULT_DIALOG_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE | MEM_DISCARDABLE;
const DEFAULT_ICON_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_DISCARDABLE;
const DEFAULT_GROUP_ICON_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE | MEM_DISCARDABLE;
const DEFAULT_BITMAP_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE;
const DEFAULT_RCDATA_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE;
const DEFAULT_VERSION_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE;
/// brc32-observed default for `<id> ACCELERATORS` blocks: MOVEABLE | PURE,
/// **without** DISCARDABLE (verified against `wrk_tools/BCC55/Bin/brc32.exe`
/// 5.40; a folklore-busting finding — the MENU default carries DISCARDABLE
/// but ACCELERATORS does not).
const DEFAULT_ACCEL_MEM_FLAGS: u16 = MEM_MOVEABLE | MEM_PURE;

/// brc32's compiled-in default language id when no `LANGUAGE` statement
/// is present. Observed value: 0x0809 (LANG_ENGLISH | SUBLANG_ENGLISH_UK
/// per `0x09 | (0x02 << 10)`).
const DEFAULT_LANGUAGE_ID: u16 = 0x0809;

/// Bundle-count exponent: 16 strings per bundle (Win32 STRINGTABLE
/// canonical packing).
const BUNDLE_SHIFT: u32 = 4;
const BUNDLE_SIZE: usize = 1 << BUNDLE_SHIFT; // 16

/// Serialise an [`RcUnit`] to the Win32 `.res` byte stream consumed by
/// `link.exe` / `ilink` (and by mdbcc's PE `.rsrc` emitter in G3).
///
/// Layout: a 32-byte null-header sentinel, followed by one resource
/// record per non-empty bundle (across all STRINGTABLE blocks in the
/// unit, merged by `(id >> 4) + 1`). Each record is DWORD-aligned.
///
/// An empty unit (no resources) yields exactly the 32-byte null header
/// — confirmed against brc32 for an empty `.rc` file.
pub fn write_res(unit: &RcUnit) -> Vec<u8> {
    let mut out = Vec::new();
    write_null_header(&mut out);

    // brc32's emission order is a fixed type-internal order, NOT source
    // order: MENU (4) → DIALOG (5) → ACCELERATORS (9) → STRINGTABLE (6).
    // Verified empirically against brc32 5.40 by compiling the same .rc
    // with multiple source orderings and observing byte-identical .res
    // output. Folklore-busting: brc32 emits DIALOG *before* ACCELERATORS
    // (and BOTH before STRINGTABLE), not in ascending type-ordinal order.
    // The PE `.rsrc` directory tree, by contrast, *is* sorted ascending
    // (Win32 directory contract; build_rsrc handles that separately).

    // Tier 1: MENU records (one per `<id> MENU` source-block, in source
    // order). Each MENU produces a single resource (no bundling).
    for res in &unit.resources {
        let Resource::Menu(m) = res else { continue };
        let data = write_menu_bytes(m);
        let mem_flags = menu_mem_flags(&m.flags);
        let lang = resolve_language(m.language.as_ref(), unit.language.as_ref());
        write_resource_header(&mut out, data.len() as u32, RT_MENU, &m.id, mem_flags, lang);
        out.extend_from_slice(&data);
        pad_to_dword(&mut out);
    }

    // Tier 2: DIALOG records (one per `<id> DIALOG` source-block).
    for res in &unit.resources {
        let Resource::Dialog(d) = res else { continue };
        let data = write_dialog_bytes(d);
        let mem_flags = dialog_mem_flags(&d.flags);
        let lang = resolve_language(d.language.as_ref(), unit.language.as_ref());
        write_resource_header(
            &mut out,
            data.len() as u32,
            RT_DIALOG,
            &d.id,
            mem_flags,
            lang,
        );
        out.extend_from_slice(&data);
        pad_to_dword(&mut out);
    }

    // Tier 3: binary resources. Full railc fidelity will move this to the
    // BC4.5 source-order profile in gap 6; this tier keeps existing ordinal
    // corpus behavior stable while adding the new payload encoders.
    for res in &unit.resources {
        match res {
            Resource::Icon(i) => {
                let lang = resolve_language(i.language.as_ref(), unit.language.as_ref());
                let icon_name = ResId::Ord(i.ordinal);
                write_resource_header(
                    &mut out,
                    i.image_data.len() as u32,
                    RT_ICON,
                    &icon_name,
                    icon_mem_flags(&i.flags),
                    lang,
                );
                out.extend_from_slice(&i.image_data);
                pad_to_dword(&mut out);

                write_resource_header(
                    &mut out,
                    i.group_data.len() as u32,
                    RT_GROUP_ICON,
                    &i.id,
                    group_icon_mem_flags(&i.flags),
                    lang,
                );
                out.extend_from_slice(&i.group_data);
                pad_to_dword(&mut out);
            }
            Resource::Bitmap(b) => {
                let lang = resolve_language(b.language.as_ref(), unit.language.as_ref());
                write_resource_header(
                    &mut out,
                    b.data.len() as u32,
                    RT_BITMAP,
                    &b.id,
                    bitmap_mem_flags(&b.flags),
                    lang,
                );
                out.extend_from_slice(&b.data);
                pad_to_dword(&mut out);
            }
            Resource::RcData(r) => {
                let lang = resolve_language(r.language.as_ref(), unit.language.as_ref());
                write_resource_header(
                    &mut out,
                    r.data.len() as u32,
                    RT_RCDATA,
                    &r.id,
                    rcdata_mem_flags(&r.flags),
                    lang,
                );
                out.extend_from_slice(&r.data);
                pad_to_dword(&mut out);
            }
            Resource::VersionInfo(v) => {
                let data = write_versioninfo_bytes(v);
                let lang = resolve_language(v.language.as_ref(), unit.language.as_ref());
                write_resource_header(
                    &mut out,
                    data.len() as u32,
                    RT_VERSION,
                    &v.id,
                    version_mem_flags(&v.flags),
                    lang,
                );
                out.extend_from_slice(&data);
                pad_to_dword(&mut out);
            }
            _ => {}
        }
    }

    // Tier 4: ACCELERATORS records (one per source block, in source order).
    for res in &unit.resources {
        let Resource::Accelerators(a) = res else {
            continue;
        };
        let data = write_accel_bytes(a);
        let mem_flags = accel_mem_flags(&a.flags);
        let lang = resolve_language(a.language.as_ref(), unit.language.as_ref());
        write_resource_header(
            &mut out,
            data.len() as u32,
            RT_ACCELERATOR,
            &a.id,
            mem_flags,
            lang,
        );
        out.extend_from_slice(&data);
        pad_to_dword(&mut out);
    }

    // Tier 5: STRINGTABLE bundles (one record per non-empty bundle,
    // ascending by bundle id). Unchanged from G2.
    let bundles = collect_bundles(unit);
    let mut bundle_ids: Vec<u16> = bundles.keys().copied().collect();
    bundle_ids.sort_unstable();

    for bundle_id in bundle_ids {
        let (slots, flags, lang) = &bundles[&bundle_id];
        let data = encode_bundle_data(slots);
        write_resource_header(
            &mut out,
            data.len() as u32,
            RT_STRING,
            &ResId::Ord(bundle_id),
            *flags,
            *lang,
        );
        out.extend_from_slice(&data);
        pad_to_dword(&mut out);
    }

    out
}

/// Serialise an [`RcUnit`] using the BC4.5-era profile needed by the RailC
/// golden resource file: non-STRING resources are emitted in source order,
/// RT_STRING bundles are emitted last, and the implicit language id is 0.
pub fn write_res_bc45(unit: &RcUnit) -> Vec<u8> {
    let mut out = Vec::new();
    write_null_header(&mut out);

    for res in &unit.resources {
        if !matches!(res, Resource::StringTable(_)) {
            write_source_order_record(&mut out, res, unit, 0);
        }
    }

    write_string_bundles(&mut out, unit, 0);
    out
}

fn write_source_order_record(
    out: &mut Vec<u8>,
    res: &Resource,
    unit: &RcUnit,
    default_language_id: u16,
) {
    match res {
        Resource::Menu(m) => {
            let data = write_menu_bytes(m);
            let mem_flags = menu_mem_flags(&m.flags);
            let lang = resolve_language_with_default(
                m.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            write_resource_header(out, data.len() as u32, RT_MENU, &m.id, mem_flags, lang);
            out.extend_from_slice(&data);
            pad_to_dword(out);
        }
        Resource::Dialog(d) => {
            let data = write_dialog_bytes(d);
            let mem_flags = dialog_mem_flags(&d.flags);
            let lang = resolve_language_with_default(
                d.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            write_resource_header(out, data.len() as u32, RT_DIALOG, &d.id, mem_flags, lang);
            out.extend_from_slice(&data);
            pad_to_dword(out);
        }
        Resource::Icon(i) => {
            let lang = resolve_language_with_default(
                i.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            let icon_name = ResId::Ord(i.ordinal);
            write_resource_header(
                out,
                i.image_data.len() as u32,
                RT_ICON,
                &icon_name,
                icon_mem_flags(&i.flags),
                lang,
            );
            out.extend_from_slice(&i.image_data);
            pad_to_dword(out);

            write_resource_header(
                out,
                i.group_data.len() as u32,
                RT_GROUP_ICON,
                &i.id,
                group_icon_mem_flags(&i.flags),
                lang,
            );
            out.extend_from_slice(&i.group_data);
            pad_to_dword(out);
        }
        Resource::Bitmap(b) => {
            let data = &b.data;
            let lang = resolve_language_with_default(
                b.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            write_resource_header(
                out,
                data.len() as u32,
                RT_BITMAP,
                &b.id,
                bitmap_mem_flags(&b.flags),
                lang,
            );
            out.extend_from_slice(data);
            pad_to_dword(out);
        }
        Resource::RcData(r) => {
            let data = &r.data;
            let lang = resolve_language_with_default(
                r.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            write_resource_header(
                out,
                data.len() as u32,
                RT_RCDATA,
                &r.id,
                rcdata_mem_flags(&r.flags),
                lang,
            );
            out.extend_from_slice(data);
            pad_to_dword(out);
        }
        Resource::VersionInfo(v) => {
            let data = write_versioninfo_bytes(v);
            let lang = resolve_language_with_default(
                v.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            write_resource_header(
                out,
                data.len() as u32,
                RT_VERSION,
                &v.id,
                version_mem_flags(&v.flags),
                lang,
            );
            out.extend_from_slice(&data);
            pad_to_dword(out);
        }
        Resource::Accelerators(a) => {
            let data = write_accel_bytes(a);
            let mem_flags = accel_mem_flags(&a.flags);
            let lang = resolve_language_with_default(
                a.language.as_ref(),
                unit.language.as_ref(),
                default_language_id,
            );
            write_resource_header(
                out,
                data.len() as u32,
                RT_ACCELERATOR,
                &a.id,
                mem_flags,
                lang,
            );
            out.extend_from_slice(&data);
            pad_to_dword(out);
        }
        Resource::StringTable(_) => {}
    }
}

/// 32-byte all-zero resource sentinel that every `.res` file starts
/// with. Differs from a real ResHeader only in that the type/name
/// ordinals are both 0 (rather than e.g. RT_STRING / bundle-id).
fn write_null_header(out: &mut Vec<u8>) {
    write_u32_le(out, 0); // data_size
    write_u32_le(out, 32); // header_size
    write_u16_le(out, ORDINAL_MARKER);
    write_u16_le(out, 0); // type ordinal = 0 (null)
    write_u16_le(out, ORDINAL_MARKER);
    write_u16_le(out, 0); // name ordinal = 0 (null)
    write_u32_le(out, 0); // data_version
    write_u16_le(out, 0); // memory_flags
    write_u16_le(out, 0); // language_id
    write_u32_le(out, 0); // version
    write_u32_le(out, 0); // characteristics
}

/// Write a 32-byte ResHeader for a record whose type and name are both
/// u16 ordinals (the only case relevant to RT_STRING in v1). `data_size`
/// is the byte length of the data payload, excluding any trailing pad.
fn write_resource_header(
    out: &mut Vec<u8>,
    data_size: u32,
    type_ord: u16,
    name: &ResId,
    mem_flags: u16,
    language_id: u16,
) {
    let mut hdr = Vec::new();
    write_u32_le(&mut hdr, data_size);
    write_u32_le(&mut hdr, 0); // patched after variable-length type/name fields
    write_u16_le(&mut hdr, ORDINAL_MARKER);
    write_u16_le(&mut hdr, type_ord);
    write_resid_name(&mut hdr, name);
    pad_to_dword(&mut hdr);
    write_u32_le(&mut hdr, 0); // data_version
    write_u16_le(&mut hdr, mem_flags);
    write_u16_le(&mut hdr, language_id);
    write_u32_le(&mut hdr, 0); // version
    write_u32_le(&mut hdr, 0); // characteristics
    let header_size = hdr.len() as u32;
    hdr[4..8].copy_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&hdr);
}

fn write_resid_name(out: &mut Vec<u8>, id: &ResId) {
    match id {
        ResId::Ord(ord) => {
            write_u16_le(out, ORDINAL_MARKER);
            write_u16_le(out, *ord);
        }
        ResId::Name(name) => {
            write_utf16le_nul(out, name);
        }
    }
}

fn write_string_bundles(out: &mut Vec<u8>, unit: &RcUnit, default_language_id: u16) {
    let bundles = collect_bundles_with_default(unit, default_language_id);
    let mut bundle_ids: Vec<u16> = bundles.keys().copied().collect();
    bundle_ids.sort_unstable();

    for bundle_id in bundle_ids {
        let (slots, flags, lang) = &bundles[&bundle_id];
        let data = encode_bundle_data(slots);
        write_resource_header(
            out,
            data.len() as u32,
            RT_STRING,
            &ResId::Ord(bundle_id),
            *flags,
            *lang,
        );
        out.extend_from_slice(&data);
        pad_to_dword(out);
    }
}

// ---- G4: MENU + ACCELERATORS payload encoders ------------------------------

/// MF_* item-flag bits the writer owns: MF_POPUP marks a submenu entry,
/// MF_END marks the last sibling at each nesting level. The other MF_*
/// bits (GRAYED=0x01, INACTIVE=0x02, CHECKED=0x08, MENUBARBREAK=0x20,
/// MENUBREAK=0x40, HELP=0x4000) arrive on `MenuItem::Item::flags` /
/// `MenuItem::Popup::flags` from the parser (G-fix-1 / MAJOR-1); the
/// writer OR's them with the position-derived MF_POPUP/MF_END bits.
const MF_POPUP: u16 = 0x0010;
const MF_END: u16 = 0x0080;

/// Encode a `<id> MENU` block to its `.res` payload bytes.
///
/// Layout:
/// ```text
///   MenuHeader (4 B): u16 wVersion=0, u16 wOffset=0
///   MenuItem (recursive):
///     u16 fItemFlags  (MF_POPUP set if popup; MF_END set on last sibling)
///     u16 wMenuID     (present only when MF_POPUP is NOT set)
///     wchar_t text[]  (UTF-16LE, null-terminated)
///     (if MF_POPUP, the popup's nested items follow directly)
/// ```
///
/// SEPARATOR is encoded as a leaf item with empty text (just a u16 0
/// terminator) and id 0 — NOT as the MF_SEPARATOR bit. (Folklore-busting:
/// brc32 5.40 does NOT set MF_SEPARATOR=0x0800; verified against the
/// differential corpus. The OS treats an empty-text zero-id item as a
/// separator at draw time.)
pub(crate) fn write_menu_bytes(menu: &MenuResource) -> Vec<u8> {
    let mut out = Vec::new();
    // MenuHeader: classic MENU (not MENUEX). MENUEX would set wVersion=1.
    write_u16_le(&mut out, 0); // wVersion
    write_u16_le(&mut out, 0); // wOffset
    write_menu_items(&mut out, &menu.items);
    out
}

/// Recursive emitter for a sibling list of menu items. The last sibling
/// gets MF_END set.
fn write_menu_items(out: &mut Vec<u8>, items: &[MenuItem]) {
    let last = items.len().saturating_sub(1);
    for (i, item) in items.iter().enumerate() {
        let is_last = i == last;
        let end_bit = if is_last { MF_END } else { 0 };
        match item {
            MenuItem::Item { text, id, flags } => {
                let bits = flags & !(MF_POPUP | MF_END) | end_bit;
                write_u16_le(out, bits);
                write_u16_le(out, *id);
                write_utf16le_nul(out, text);
            }
            MenuItem::Separator => {
                // Empty text, id 0. brc32 emits flags = MF_END (or 0 when
                // not last) with no MF_SEPARATOR bit.
                write_u16_le(out, end_bit);
                write_u16_le(out, 0);
                write_u16_le(out, 0); // empty UTF-16LE string = just the NUL
            }
            MenuItem::Popup { text, flags, items } => {
                let bits = (flags & !(MF_POPUP | MF_END)) | MF_POPUP | end_bit;
                write_u16_le(out, bits);
                write_utf16le_nul(out, text);
                write_menu_items(out, items);
            }
        }
    }
}

/// Encode an `<id> ACCELERATORS` block to its `.res` payload bytes.
///
/// Layout:
/// ```text
///   ACCELTABLEENTRY (8 B each):
///     u8  fFlags  (FACCEL_* bits; FACCEL_LAST=0x80 on the final entry)
///     u8  pad     = 0
///     u16 key     (VK code or ASCII char, per fFlags & FACCEL_VIRTKEY)
///     u16 cmd     (WM_COMMAND id)
///     u16 pad     = 0
/// ```
pub(crate) fn write_accel_bytes(accel: &AcceleratorTable) -> Vec<u8> {
    let mut out = Vec::new();
    let last = accel.entries.len().saturating_sub(1);
    for (i, e) in accel.entries.iter().enumerate() {
        let mut f = e.flags;
        if i == last {
            f |= 0x80; // FACCEL_LAST
        }
        out.push(f);
        out.push(0); // pad
        write_u16_le(&mut out, e.key);
        write_u16_le(&mut out, e.cmd);
        write_u16_le(&mut out, 0); // pad
    }
    out
}

/// Encode a UTF-8 source string as UTF-16LE with a trailing u16 NUL.
fn write_utf16le_nul(out: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        write_u16_le(out, u);
    }
    write_u16_le(out, 0);
}

// ---- W5 rc gap 8: VERSIONINFO payload encoder ----------------------------

/// Encode a `<id> VERSIONINFO` block to the standard Win32
/// `VS_VERSION_INFO` payload.
pub(crate) fn write_versioninfo_bytes(info: &VersionInfoResource) -> Vec<u8> {
    let mut out = Vec::new();
    let root = begin_version_node(&mut out, 52, 0, "VS_VERSION_INFO");
    write_fixed_file_info(&mut out, &info.fixed);
    write_version_children(&mut out, &info.children);
    finish_version_node(&mut out, root);
    out
}

fn write_fixed_file_info(out: &mut Vec<u8>, fixed: &VersionFixedInfo) {
    write_u32_le(out, 0xFEEF_04BD); // dwSignature
    write_u32_le(out, 0x0001_0000); // dwStrucVersion
    write_version_ms_ls(out, fixed.file_version);
    write_version_ms_ls(out, fixed.product_version);
    write_u32_le(out, fixed.file_flags_mask);
    write_u32_le(out, fixed.file_flags);
    write_u32_le(out, fixed.file_os);
    write_u32_le(out, fixed.file_type);
    write_u32_le(out, fixed.file_subtype);
    write_u32_le(out, 0); // dwFileDateMS
    write_u32_le(out, 0); // dwFileDateLS
}

fn write_version_ms_ls(out: &mut Vec<u8>, quad: [u16; 4]) {
    write_u32_le(out, ((quad[0] as u32) << 16) | quad[1] as u32);
    write_u32_le(out, ((quad[2] as u32) << 16) | quad[3] as u32);
}

fn write_version_children(out: &mut Vec<u8>, children: &[VersionNode]) {
    for child in children {
        pad_to_dword(out);
        write_version_node(out, child);
    }
}

fn write_version_node(out: &mut Vec<u8>, node: &VersionNode) {
    match node {
        VersionNode::Block { key, children } => {
            let start = begin_version_node(out, 0, 0, key);
            write_version_children(out, children);
            finish_version_node(out, start);
        }
        VersionNode::Value { key, value } => {
            let utf16: Vec<u16> = value.encode_utf16().collect();
            let value_len = u16::try_from(utf16.len()).unwrap_or(u16::MAX);
            let start = begin_version_node(out, value_len, 1, key);
            for unit in utf16 {
                write_u16_le(out, unit);
            }
            finish_version_node(out, start);
        }
    }
}

fn begin_version_node(out: &mut Vec<u8>, value_len: u16, value_type: u16, key: &str) -> usize {
    let start = out.len();
    write_u16_le(out, 0); // patched by finish_version_node
    write_u16_le(out, value_len);
    write_u16_le(out, value_type);
    write_utf16le_nul(out, key);
    pad_to_dword(out);
    start
}

fn finish_version_node(out: &mut [u8], start: usize) {
    let len = u16::try_from(out.len() - start).unwrap_or(u16::MAX);
    out[start..start + 2].copy_from_slice(&len.to_le_bytes());
}

// ---- G5a: DIALOG payload encoder ------------------------------------------

/// Encode a `<id> DIALOG` block to its `.res` payload bytes.
///
/// Layout (classic `DLGTEMPLATE`; the `DLGTEMPLATEEX` form is unsupported
/// — source-level `DIALOGEX` is rejected by the parser per G-fix-2 /
/// MAJOR-2, so this function is unreachable for the EX form):
/// ```text
///   DWORD style; DWORD dwExtendedStyle;
///   WORD cdit; SHORT x, y, cx, cy;
///   sz_Or_Ord menu;
///   sz_Or_Ord windowClass;
///   sz_Or_Ord title;        -- always a string here (NUL only when no
///                              CAPTION; ordinal form not used in v1)
///   [WORD pointSize; sz title-typeface;] -- iff DS_SETFONT set in style
///   align to DWORD;
///   DLGITEMTEMPLATE × cdit  -- each DWORD-aligned (see below)
/// ```
///
/// DLGITEMTEMPLATE shape:
/// ```text
///   DWORD style; DWORD dwExtendedStyle;
///   SHORT x, y, cx, cy;
///   WORD id;
///   sz_Or_Ord windowClass;  -- predefined ⇒ {0xFFFF, ord}; user ⇒ string
///   sz_Or_Ord title;        -- ordinal (ICON) or string
///   WORD creationDataLen = 0;
///   align to DWORD;
/// ```
pub(crate) fn write_dialog_bytes(dlg: &DialogResource) -> Vec<u8> {
    let mut out = Vec::new();
    let cdit = u16::try_from(dlg.controls.len()).unwrap_or(u16::MAX);

    write_u32_le(&mut out, dlg.style);
    write_u32_le(&mut out, dlg.ex_style);
    write_u16_le(&mut out, cdit);
    write_i16_le(&mut out, dlg.x);
    write_i16_le(&mut out, dlg.y);
    write_i16_le(&mut out, dlg.cx);
    write_i16_le(&mut out, dlg.cy);

    // menu: u16 0 if absent; ordinal form if numeric; UTF-16LE string + NUL.
    write_resref(&mut out, dlg.menu.as_ref());
    // windowClass: u16 0 = standard "#32770" dialog class.
    write_resref(&mut out, dlg.class.as_ref());
    // title: UTF-16LE NUL string (just NUL when no CAPTION).
    write_utf16le_nul(&mut out, dlg.caption.as_deref().unwrap_or(""));

    // FONT trailer — present iff DS_SETFONT set in style. (We OR'd the bit
    // in at parse time; the AST's `font` field is the source of truth.)
    if let Some((pt, ref typeface)) = dlg.font {
        write_u16_le(&mut out, pt);
        write_utf16le_nul(&mut out, typeface);
    }

    // Align to DWORD before first DLGITEMTEMPLATE. Between items we pad
    // to DWORD before the *next* item (so item N+1 starts aligned).
    // brc32 does NOT pad after the last item — the .res record-level pad
    // does that. Including it here would over-report data_size by up to
    // 3 bytes.
    pad_to_dword(&mut out);

    let last = dlg.controls.len().saturating_sub(1);
    for (i, ctrl) in dlg.controls.iter().enumerate() {
        write_dialog_control(&mut out, ctrl);
        if i != last {
            pad_to_dword(&mut out);
        }
    }
    out
}

/// Emit one DLGITEMTEMPLATE record. No trailing pad — the caller is
/// responsible for the alignment between items so an empty-controls
/// dialog stays clean (no spurious trailing zeros).
fn write_dialog_control(out: &mut Vec<u8>, ctrl: &DialogControl) {
    write_u32_le(out, ctrl.style);
    write_u32_le(out, ctrl.ex_style);
    write_i16_le(out, ctrl.x);
    write_i16_le(out, ctrl.y);
    write_i16_le(out, ctrl.cx);
    write_i16_le(out, ctrl.cy);
    write_u16_le(out, ctrl.id as u16);
    match &ctrl.class {
        ControlClass::Predefined(ord) => {
            write_u16_le(out, 0xFFFF);
            write_u16_le(out, *ord);
        }
        ControlClass::UserClass(s) => {
            write_utf16le_nul(out, s);
        }
    }
    write_resref(out, Some(&ctrl.text));
    write_u16_le(out, 0); // creationDataLen
}

/// Emit a `sz_Or_Ord` field. The `menu`/`windowClass`/control-title
/// fields all share this encoding. `None` ⇒ a single `u16 0x0000`
/// (meaning "absent" — for menu and class this is "use defaults"; for
/// control title this case is unused as titles default to the empty
/// string).
fn write_resref(out: &mut Vec<u8>, r: Option<&ResRef>) {
    match r {
        None => write_u16_le(out, 0x0000),
        Some(ResRef::Numeric(ord)) => {
            write_u16_le(out, 0xFFFF);
            write_u16_le(out, *ord);
        }
        Some(ResRef::Name(s)) => {
            write_utf16le_nul(out, s);
        }
    }
}

/// Per-block memory-flags computation for DIALOG (matches MENU).
fn dialog_mem_flags(flags: &super::MemoryFlags) -> u16 {
    let mut bits = DEFAULT_DIALOG_MEM_FLAGS;
    if flags.preload {
        bits |= MEM_PRELOAD;
    }
    if flags.fixed {
        bits &= !MEM_MOVEABLE;
    }
    bits
}

fn icon_mem_flags(flags: &super::MemoryFlags) -> u16 {
    apply_common_binary_flags(DEFAULT_ICON_MEM_FLAGS, flags)
}

fn group_icon_mem_flags(flags: &super::MemoryFlags) -> u16 {
    apply_common_binary_flags(DEFAULT_GROUP_ICON_MEM_FLAGS, flags)
}

fn bitmap_mem_flags(flags: &super::MemoryFlags) -> u16 {
    apply_common_binary_flags(DEFAULT_BITMAP_MEM_FLAGS, flags)
}

fn rcdata_mem_flags(flags: &super::MemoryFlags) -> u16 {
    apply_common_binary_flags(DEFAULT_RCDATA_MEM_FLAGS, flags)
}

fn version_mem_flags(flags: &super::MemoryFlags) -> u16 {
    apply_common_binary_flags(DEFAULT_VERSION_MEM_FLAGS, flags)
}

fn apply_common_binary_flags(mut bits: u16, flags: &super::MemoryFlags) -> u16 {
    if flags.preload {
        bits |= MEM_PRELOAD;
    }
    if flags.fixed {
        bits &= !MEM_MOVEABLE;
    }
    if flags.discardable {
        bits |= MEM_DISCARDABLE;
    }
    bits
}

fn write_i16_le(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Per-block memory-flags computation for MENU (mirrors stringtable_mem_flags).
fn menu_mem_flags(flags: &super::MemoryFlags) -> u16 {
    let mut bits = DEFAULT_MENU_MEM_FLAGS;
    if flags.preload {
        bits |= MEM_PRELOAD;
    }
    if flags.fixed {
        bits &= !MEM_MOVEABLE;
    }
    bits
}

/// Per-block memory-flags computation for ACCELERATORS. brc32 default differs
/// from STRINGTABLE/MENU — DISCARDABLE is NOT set.
fn accel_mem_flags(flags: &super::MemoryFlags) -> u16 {
    let mut bits = DEFAULT_ACCEL_MEM_FLAGS;
    if flags.preload {
        bits |= MEM_PRELOAD;
    }
    if flags.fixed {
        bits &= !MEM_MOVEABLE;
    }
    bits
}

/// Encode the 16-slot bundle payload: exactly 16 length-prefixed
/// UTF-16LE strings, with the prefix being the count of UTF-16 code
/// units (NOT bytes). Empty slots = u16 0 (just the length prefix).
fn encode_bundle_data(slots: &[Option<String>; BUNDLE_SIZE]) -> Vec<u8> {
    let mut data = Vec::new();
    for slot in slots {
        match slot {
            None => write_u16_le(&mut data, 0),
            Some(value) => {
                let utf16: Vec<u16> = value.encode_utf16().collect();
                // The length prefix is u16; values are ≤ u16::MAX
                // because STRINGTABLE strings cap at 4097 chars per
                // rc.exe and brc32 historic limits — we still saturate
                // defensively (no panic on a pathological input).
                let len = u16::try_from(utf16.len()).unwrap_or(u16::MAX);
                write_u16_le(&mut data, len);
                for unit in utf16 {
                    write_u16_le(&mut data, unit);
                }
            }
        }
    }
    data
}

/// Group every defined string in the unit into per-bundle slot arrays,
/// tagged with the bundle's memory flags and language id. Multiple
/// STRINGTABLE blocks contribute to the same bundle when their ids
/// share `id >> 4`. brc32 uses last-write-wins within a bundle when the
/// same id is defined twice — we do the same (no error).
///
/// Returned map key = bundle id `(id >> 4) + 1`. Value = (slots, flags,
/// language). All three are taken from the **first** STRINGTABLE that
/// contributed to the bundle; this matches brc32 (verified by
/// inspection — the per-block flags/language don't merge, the bundle
/// inherits from its first emitter).
fn collect_bundles(
    unit: &RcUnit,
) -> std::collections::BTreeMap<u16, ([Option<String>; BUNDLE_SIZE], u16, u16)> {
    collect_bundles_with_default(unit, DEFAULT_LANGUAGE_ID)
}

fn collect_bundles_with_default(
    unit: &RcUnit,
    default_language_id: u16,
) -> std::collections::BTreeMap<u16, ([Option<String>; BUNDLE_SIZE], u16, u16)> {
    let mut map: std::collections::BTreeMap<u16, ([Option<String>; BUNDLE_SIZE], u16, u16)> =
        std::collections::BTreeMap::new();

    for res in &unit.resources {
        let Resource::StringTable(st) = res else {
            continue;
        };
        let block_flags = stringtable_mem_flags(&st.flags);
        let block_lang = resolve_language_with_default(
            st.language.as_ref(),
            unit.language.as_ref(),
            default_language_id,
        );

        for StringTableEntry { id, value, .. } in &st.entries {
            let bundle_id = (*id >> BUNDLE_SHIFT) + 1;
            let slot = (*id as usize) & (BUNDLE_SIZE - 1);
            let entry = map
                .entry(bundle_id)
                .or_insert_with(|| (core::array::from_fn(|_| None), block_flags, block_lang));
            entry.0[slot] = Some(value.clone());
        }
    }

    map
}

/// Compute the 16-bit `memory_flags` field brc32 writes for a
/// STRINGTABLE given its parsed source flags. Observed mapping (from
/// brc32 5.40 on the BCC55 toolchain):
///
/// - Base = `MOVEABLE | PURE | DISCARDABLE` (0x1030).
/// - `PRELOAD` sets bit 0x0040; `LOADONCALL` is a no-op (the default).
/// - `FIXED` clears the `MOVEABLE` bit (0x0010).
/// - `DISCARDABLE` is a no-op (already set in the base).
/// - `MOVEABLE` is a no-op (already set in the base).
fn stringtable_mem_flags(flags: &super::MemoryFlags) -> u16 {
    let mut bits = DEFAULT_STRINGTABLE_MEM_FLAGS;
    if flags.preload {
        bits |= MEM_PRELOAD;
    }
    if flags.fixed {
        bits &= !MEM_MOVEABLE;
    }
    bits
}

/// Resolve the language id for a bundle: per-block LANGUAGE overrides
/// file-level LANGUAGE; if neither is set, fall back to brc32's
/// compiled-in default 0x0809.
fn resolve_language(block: Option<&Language>, file: Option<&Language>) -> u16 {
    resolve_language_with_default(block, file, DEFAULT_LANGUAGE_ID)
}

fn resolve_language_with_default(
    block: Option<&Language>,
    file: Option<&Language>,
    default_language_id: u16,
) -> u16 {
    block
        .or(file)
        .map(|l| l.primary | (l.sub << 10))
        .unwrap_or(default_language_id)
}

// ---- low-level byte helpers ------------------------------------------------

fn write_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Pad `out` with zero bytes until its length is a multiple of 4. No-op
/// when already aligned. Used between records.
fn pad_to_dword(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}
