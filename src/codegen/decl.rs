//! Declaration-time emission helpers: global-variable byte images.
//!
//! At present this module holds the single free function
//! [`global_image`] — used by [`crate::codegen::compile_module`] to
//! materialise a file-scope variable's initial bytes from its type and
//! optional initializer. Block-scope local declarations are NOT routed
//! through here; they remain part of `Gen::gen_stmt`'s `Stmt::Decl` arm
//! in `src/codegen.rs` because they share the function's frame layout
//! and dtor-tracking state.
//!
//! Future S1 work (COFF emission, multi-TU) will likely add more
//! declaration-time helpers here (CRT-style `.CRT$XCU` slot synthesis,
//! `.def` parser glue, etc.). For now this is the single-file seam.
//!
//! ## O1 byte-identity invariant
//!
//! Pure refactor of pre-existing logic. Every global's initial byte
//! image is identical to before the split.

use crate::ast::{Expr, Record, Type};
use crate::codegen::CodegenError;
use crate::parser::const_eval;

/// W6 (G52): data relocations for a global's static image — `(byte offset
/// within the image, target global name, addend)`. See
/// [`crate::codegen::GlobalData::data_relocs`].
pub(crate) type DataRelocs = Vec<(usize, String, i64)>;

/// Build a global's initial bytes (constant initializer or zero-filled).
///
/// `ptr_bytes` is the target pointer width (8 = Win64, 4 = Win32) so a
/// pointer-typed global — or an aggregate transitively containing one —
/// reserves the ILP32-correct number of bytes on Win32. With `ptr_bytes == 8`
/// the image is byte-for-byte the historical Win64 output.
pub(crate) fn global_image(
    ty: &Type,
    init: Option<&Expr>,
    ptr_bytes: usize,
    records: &[Record],
) -> Result<Vec<u8>, CodegenError> {
    let (bytes, relocs) = global_image_reloc(ty, init, ptr_bytes, records)?;
    if !relocs.is_empty() {
        // Callers that cannot carry relocations (static-local images, the
        // tests' direct probes) must not silently drop them.
        return Err(CodegenError(
            "global initializer needs data relocations \
             (use global_image_reloc)"
                .into(),
        ));
    }
    Ok(bytes)
}

/// W6 (G52): like [`global_image`], but ADDRESS-CONSTANT pointer elements
/// (`&g`, `&g[k]`, casts thereof) fold into the image as `(offset, target
/// global, addend)` relocations instead of failing — Borland bakes such
/// tables (TZSET.C's `char * const _tzname[2] = {&_DfltZone[0], …}`) into
/// the static image, and the RTL's `#pragma startup` readers run before any
/// dynamic-init thunk could fill them. The addend is also written into the
/// slot bytes (COFF Addr32/Addr64 add-in-place semantics). The caller is
/// responsible for validating each target names a real data global (and
/// falling back to dynamic init otherwise — e.g. FUNCTION addresses in OWL
/// response tables stay on the proven #32 path).
pub(crate) fn global_image_reloc(
    ty: &Type,
    init: Option<&Expr>,
    ptr_bytes: usize,
    records: &[Record],
) -> Result<(Vec<u8>, DataRelocs), CodegenError> {
    let mut relocs = Vec::new();
    let bytes = image_rec(ty, init, ptr_bytes, records, 0, &mut relocs)?;
    Ok((bytes, relocs))
}

/// G52: peel an ADDRESS-CONSTANT initializer expression — `&g`, `&g[k]`
/// (with `elem` = the destination pointer's pointee size for the addend),
/// and casts around either — to `(target global name, byte addend)`.
/// `None` for anything else (incl. a BARE identifier: without the globals
/// table an array-decay `g` is indistinguishable from a runtime pointer
/// VALUE copy, so it stays on the dynamic-init path).
fn addr_const_expr(e: &Expr, elem_size: usize) -> Option<(String, i64)> {
    use crate::ast::UnOp;
    match e {
        Expr::Cast { expr, .. } => addr_const_expr(expr, elem_size),
        Expr::Unary {
            op: UnOp::Addr,
            expr,
        } => match expr.as_ref() {
            Expr::Var(g, _) => Some((g.clone(), 0)),
            Expr::Index { base, idx, .. } => match (base.as_ref(), idx.as_ref()) {
                (Expr::Var(g, _), Expr::Int(k)) => Some((g.clone(), *k * elem_size as i64)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn image_rec(
    ty: &Type,
    init: Option<&Expr>,
    ptr_bytes: usize,
    records: &[Record],
    base: usize,
    relocs: &mut Vec<(usize, String, i64)>,
) -> Result<Vec<u8>, CodegenError> {
    // Phase F-2 §F-g: a `Type::Float` global lands its IEEE-754 little-endian
    // byte image (`f64.to_le_bytes()` for double; for `bytes==4`/float the
    // double is narrowed via `as f32` then stored as 4 bytes — the C cast).
    // No `const_eval` for FP yet: a non-literal FP initializer (`1.0 + 2.0`)
    // is a clean error — narrow, honest, easy to widen later (HLD F-2
    // backlog), never silently wrong.
    if ty.is_float() {
        let bytes_n = ty.size_for(ptr_bytes).max(1);
        let value: f64 = match init {
            None => 0.0,
            Some(Expr::Float { value, .. }) => *value,
            Some(Expr::Int(v)) | Some(Expr::Char(v)) => *v as f64, // `double k = 3;` / `= 'a';`
            _ => {
                return Err(CodegenError(
                    "global FP initializer must be a literal (Phase F-2 \
                     defers FP `const_eval`)"
                        .into(),
                ));
            }
        };
        let mut bytes = vec![0u8; bytes_n];
        if bytes_n == 4 {
            bytes.copy_from_slice(&(value as f32).to_le_bytes());
        } else {
            // bytes_n == 8 (the only other Float size). `to_le_bytes()` writes
            // the IEEE-754 bit pattern in CPU byte order (little-endian on x64).
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        return Ok(bytes);
    }
    let size = ty.size_for(ptr_bytes).max(1);
    let mut bytes = vec![0u8; size];
    match init {
        None => {}
        Some(Expr::Str(s)) => {
            // G44: a string literal initializing a POINTER cannot fold to
            // constant bytes — the slot needs the literal's ADDRESS (a
            // relocation), not its characters. This arm is reached for
            // `char *` members/elements INSIDE an aggregate (LOCALE CCONV.C's
            // `struct lconv _localeconvention = { ".", "", ... }`); folding
            // used to write 0x2E into the decimal_point slot, crashing every
            // RTL %f/%e/%g conversion. Fail instead, so compile_module's #32
            // fallback routes the enclosing aggregate through dynamic init
            // (zeroed storage + startup assignments). The SCALAR global
            // `char *g = "..."` never reaches here — compile_module's
            // `ptr_str` arm intercepts it with a real relocation. A char
            // ARRAY (`char buf[8] = "abc"`) still byte-copies below.
            if matches!(ty, Type::Ptr(_)) {
                return Err(CodegenError(
                    "string literal initializing a pointer needs a \
                     relocation (dynamic-init fallback)"
                        .into(),
                ));
            }
            for (i, b) in s.iter().enumerate() {
                if i < size {
                    bytes[i] = *b;
                }
            }
            // trailing NUL already present (zero-filled)
        }
        // S4.2ac: aggregate-init globals. Const-evaluate the brace-enclosed
        // initializer into the type's byte image. `fill_aggregate` dispatches
        // by the CONTAINER (array stride / struct field offsets / union first
        // member) and recurses through `global_image` for each element, so a
        // nested `{...}`, a scalar/FP leaf, and a `char[]="..."` string element
        // all reuse the established per-element paths. Block-scope `{...}` was
        // already supported (gen_init_list_into_slot); this closes the
        // file-scope gap (RTL/CLASSLIB lookup tables — HASH.CPP's `TCharMask`).
        Some(Expr::InitList(elems)) => {
            fill_aggregate(&mut bytes, ty, elems, ptr_bytes, records, base, relocs)?;
        }
        Some(e) => {
            // G52: an ADDRESS-CONSTANT pointer leaf (`&g` / `&g[k]`) becomes
            // a data relocation — addend into the slot, symbol added by the
            // linker. Everything else keeps the historical const_eval path
            // (null / absolute-integer pointers fold; non-constants error
            // into the caller's dynamic-init fallback).
            if let Type::Ptr(pointee) = ty
                && let Some((target, addend)) =
                    addr_const_expr(e, pointee.size_for(ptr_bytes).max(1))
            {
                relocs.push((base, target, addend));
                let le = addend.to_le_bytes();
                bytes[..size.min(8)].copy_from_slice(&le[..size.min(8)]);
            } else {
                let v = const_eval(e)
                    .ok_or_else(|| CodegenError("global initializer must be a constant".into()))?;
                let le = v.to_le_bytes();
                bytes[..size.min(8)].copy_from_slice(&le[..size.min(8)]);
            }
        }
    }
    Ok(bytes)
}

/// S4.2ac: recursively fill `out` (the container's zeroed byte image) from a
/// brace-enclosed aggregate initializer. Dispatches by the CONTAINER type;
/// each element is materialised by [`global_image`], so a nested `{...}`, a
/// scalar/FP leaf, or a `char[]="..."` string element all reuse the
/// established per-element logic. Excess initializers past the array bound /
/// field count are ignored (matching the block-scope path); missing ones stay
/// zero (C's static zero-initialisation).
fn fill_aggregate(
    out: &mut [u8],
    ty: &Type,
    elems: &[Expr],
    ptr_bytes: usize,
    records: &[Record],
    base: usize,
    relocs: &mut Vec<(usize, String, i64)>,
) -> Result<(), CodegenError> {
    match ty {
        Type::Array(elem, n) => {
            let stride = elem.size_for(ptr_bytes).max(1);
            for (i, e) in elems.iter().enumerate().take(*n) {
                let off = i * stride;
                let sub = image_rec(elem, Some(e), ptr_bytes, records, base + off, relocs)?;
                let cnt = sub.len().min(out.len().saturating_sub(off));
                out[off..off + cnt].copy_from_slice(&sub[..cnt]);
            }
        }
        Type::Record { id, .. } => {
            let rec = records
                .get(*id)
                .ok_or_else(|| CodegenError("aggregate init: unknown record id".into()))?;
            // A union initialises only its first member; a struct maps each
            // initializer to the field at the same index (its byte offset).
            let field_count = if rec.is_union {
                rec.fields.len().min(1)
            } else {
                rec.fields.len()
            };
            for (i, e) in elems.iter().enumerate().take(field_count) {
                let f = &rec.fields[i];
                let sub = image_rec(&f.ty, Some(e), ptr_bytes, records, base + f.offset, relocs)?;
                let cnt = sub.len().min(out.len().saturating_sub(f.offset));
                out[f.offset..f.offset + cnt].copy_from_slice(&sub[..cnt]);
            }
        }
        _ => {
            // A braced scalar `int x = {5};` — take the first element.
            if let Some(e) = elems.first() {
                let sub = image_rec(ty, Some(e), ptr_bytes, records, base, relocs)?;
                let cnt = sub.len().min(out.len());
                out[..cnt].copy_from_slice(&sub[..cnt]);
            }
        }
    }
    Ok(())
}
