//! S4.1b — function-template **monomorphisation**.
//!
//! A pre-codegen pass that turns a TU containing function templates into an
//! ordinary template-free TU: for every call to a function template it deduces
//! the type arguments from the call's argument types, instantiates one
//! concrete [`Function`] per distinct type-argument set (cloning the generic
//! and substituting each [`Type::TemplateParam`] for the deduced type), and
//! rewrites the call to name that instantiation. The instantiations are added
//! as ordinary `Item::Func`s, so the existing codegen + call machinery handles
//! them with zero new lowering: an in-TU function's call symbol is its raw
//! name (see `gen_call_with_lead`'s bare-name path), and an instantiation is a
//! plain non-overloaded function, so its definition and every rewritten call
//! agree on the mangled name.
//!
//! Invoked by [`compile_module_for`] ONLY when `tu.fn_templates` is non-empty,
//! so a TU with no template is byte-identical (this module never runs for it).
//!
//! ## Scope (S4.1b)
//! Deduction from argument types where the parameter is *directly* a template
//! parameter (`T`), against literal / variable / cast argument expressions —
//! the overwhelmingly common case and all OWL needs to start. Pointer/ref
//! parameter patterns (`T*`, `const T&`), explicit `f<int>(…)`, and non-type
//! parameters are deferred (clean error) until a real header demands them.

use crate::ast::{BinOp, Expr, Function, Item, Record, Stmt, TemplateDecl, TranslationUnit, Type};
use crate::codegen::CodegenError;
use crate::codegen::cpp::borland_mangle_type;
use std::collections::{HashMap, HashSet};

/// G13: the immutable type context threaded through instantiation so
/// [`subst_type`] can resolve a DEPENDENT nested type (`Base::Streamer`) once
/// the outer template parameter is bound to a concrete record. `records`
/// supplies the bound record's tag (and the nested record's size/align);
/// `nested` is the TU's scoped `Outer::Inner -> id` map (#64).
struct Tcx<'a> {
    records: &'a [Record],
    nested: &'a HashMap<String, usize>,
    /// #26c: function name → return type, for deducing a template argument from
    /// a CALL result (OWL `ToBool(::GetClassInfo(...))` ⇒ `T = int`). Built from
    /// the TU's definitions + extern prototypes (Win32 API decls included).
    fn_rets: &'a HashMap<String, Type>,
}

/// Transform `tu` (which has ≥1 function template) into an equivalent
/// template-free TU: instantiations appended to `items`, template calls
/// rewritten, `fn_templates` cleared.
pub(crate) fn monomorphize(tu: &TranslationUnit) -> Result<TranslationUnit, CodegenError> {
    let mut out = tu.clone();
    // S4 (#27): a name may have MULTIPLE function-template overloads (CLASSLIB
    // STDTEMPL.H declares both `min(T,T)` and `min(T,T,T)`). Group them by name
    // so a call resolves to the arity-matching overload — a `HashMap<String,
    // TemplateDecl>` collapsed overloads (last wins), leaving an arity-mismatched
    // call un-instantiated and unresolved at link.
    let mut templates: HashMap<String, Vec<TemplateDecl>> = HashMap::new();
    for t in &tu.fn_templates {
        templates
            .entry(t.func.name.clone())
            .or_default()
            .push(t.clone());
    }

    // Names of instantiations already created (dedup across all call sites).
    let mut created: HashSet<String> = HashSet::new();
    // File-scope globals contribute to deduction scope (a global passed to a
    // template). Records are needed only to carry sizes (deduction is by type
    // identity, so a clone of the table is enough).
    let globals = collect_globals(tu);

    // Fixpoint: scan every function body, rewrite template calls, collect new
    // instantiations; repeat until a pass adds none (an instantiation body may
    // itself call a template). Re-scanning rewritten calls is harmless — their
    // names are no longer template names.
    // S4.2g: functions DEFERRED because a template call in their body cannot be
    // deduced/instantiated yet (e.g. OWL's `ToBool<T>` against a reference param,
    // or a body that needs reference-to-temporary codegen). Rather than failing
    // the whole TU, the function is dropped and a diagnostic is emitted. This is
    // an interim move toward inline-on-demand emission: a header's UNREACHABLE
    // inline bodies (which a real compiler never instantiates) stop blocking
    // compilation. Safe BY CONSTRUCTION — it fires only where the old code already
    // ERRORED, so every program that compiled before (incl. the 88 byte-identical
    // baselines) is byte-for-byte unchanged. A reference to a dropped function is
    // a loud link-time "undefined symbol", never a silent miscompile.
    let mut dropped: HashSet<usize> = HashSet::new();
    let mut deferred: Vec<String> = Vec::new();
    // G13: type context for dependent-nested-type resolution during instantiation
    // (`Base::Streamer` → the concrete nested record). Borrowed from the input TU
    // (immutable for the whole pass), so it never conflicts with `out.items`
    // mutation below.
    // #26c: function-name → return-type map for CALL-result deduction.
    let mut fn_rets: HashMap<String, Type> = HashMap::new();
    for item in &tu.items {
        if let Item::Func(f) = item {
            fn_rets
                .entry(f.name.clone())
                .or_insert_with(|| f.ret.clone());
        }
    }
    for p in &tu.extern_protos {
        fn_rets
            .entry(p.name.clone())
            .or_insert_with(|| p.ret.clone());
    }
    let tcx = Tcx {
        records: &tu.records,
        nested: &tu.nested_scopes,
        fn_rets: &fn_rets,
    };
    loop {
        let mut new_funcs: Vec<Function> = Vec::new();
        let mut idx = 0;
        while idx < out.items.len() {
            if !dropped.contains(&idx)
                && let Item::Func(f) = &out.items[idx]
            {
                let scope = fn_scope(f, &globals);
                // Clone the body, rewrite on the clone, then store back (avoids
                // borrowing `out.items` mutably while reading `templates`).
                let mut body = f.body.clone();
                match rewrite_stmts(
                    &mut body,
                    &templates,
                    &scope,
                    &mut created,
                    &mut new_funcs,
                    &tcx,
                ) {
                    Ok(()) => {
                        if let Item::Func(f) = &mut out.items[idx] {
                            f.body = body;
                        }
                    }
                    Err(_) => {
                        if let Item::Func(f) = &out.items[idx] {
                            deferred.push(f.name.clone());
                        }
                        dropped.insert(idx);
                    }
                }
            }
            idx += 1;
        }
        if new_funcs.is_empty() {
            break;
        }
        for f in new_funcs {
            out.items.push(Item::Func(f));
        }
    }
    // Remove deferred functions (highest index first so earlier indices stay
    // valid). Only appends happened during the loop, so these indices are stable.
    let mut idxs: Vec<usize> = dropped.into_iter().collect();
    idxs.sort_unstable_by(|a, b| b.cmp(a));
    for i in idxs {
        out.items.remove(i);
    }
    if !deferred.is_empty() {
        crate::diag::note(
            crate::diag::NoteKind::Deferred,
            deferred.len(),
            format!(
                "note: deferred {} function(s) with not-yet-instantiable template \
                 calls (S4.2g): {}",
                deferred.len(),
                deferred.join(", ")
            ),
        );
    }

    out.fn_templates.clear();
    Ok(out)
}

/// Flat name→type scope for deduction: a function's parameters plus every
/// local declaration in its body (block nesting flattened — good enough for
/// deducing a template call's argument types), over the file-scope globals.
fn fn_scope(f: &Function, globals: &HashMap<String, Type>) -> HashMap<String, Type> {
    let mut scope = globals.clone();
    for (n, t) in &f.params {
        scope.insert(n.clone(), t.clone());
    }
    collect_decls(&f.body, &mut scope);
    scope
}

fn collect_globals(tu: &TranslationUnit) -> HashMap<String, Type> {
    let mut g = HashMap::new();
    for item in &tu.items {
        if let Item::Global { name, ty, .. } = item {
            g.insert(name.clone(), ty.clone());
        }
    }
    g
}

fn collect_decls(stmts: &[Stmt], out: &mut HashMap<String, Type>) {
    for s in stmts {
        match s {
            Stmt::Decl { name, ty, .. } => {
                out.insert(name.clone(), ty.clone());
            }
            Stmt::Block(b, _) => collect_decls(b, out),
            Stmt::If { then, els, .. } => {
                collect_decls(std::slice::from_ref(then), out);
                if let Some(e) = els {
                    collect_decls(std::slice::from_ref(e), out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_decls(std::slice::from_ref(body), out)
            }
            Stmt::For { init, body, .. } => {
                if let Some(i) = init {
                    collect_decls(std::slice::from_ref(i), out);
                }
                collect_decls(std::slice::from_ref(body), out);
            }
            Stmt::Switch { body, .. } => collect_decls(std::slice::from_ref(body), out),
            _ => {}
        }
    }
}

/// Best-effort static type of an argument expression, for template deduction.
/// `None` ⇒ undeducible in S4.1b (a clean error at the call site).
fn type_of_expr(e: &Expr, scope: &HashMap<String, Type>, tcx: &Tcx) -> Option<Type> {
    match e {
        Expr::Int(_) => Some(Type::Int {
            bytes: 4,
            signed: true,
        }),
        Expr::Char(_) => Some(Type::Int {
            bytes: 1,
            signed: true,
        }),
        Expr::Float { bytes, .. } => Some(Type::Float { bytes: *bytes }),
        // A string literal decays to `char *`.
        Expr::Str(_) => Some(Type::Ptr(Box::new(Type::Int {
            bytes: 1,
            signed: true,
        }))),
        Expr::Var(name, _) => scope.get(name).cloned(),
        Expr::Cast { ty, .. } => Some(ty.clone()),
        // #26c: a free-function CALL has its declared return type — lets a
        // template argument deduce from a call result. OWL's `TWindow::Register`
        // does `ToBool(::GetClassInfo(...))`; `T` must come from the BOOL-returning
        // API call, which is otherwise un-typeable here. The leading `::` of a
        // global-scope call is stripped to match the proto name.
        Expr::Call { name, .. } => {
            let key = name.strip_prefix("::").unwrap_or(name);
            tcx.fn_rets.get(key).cloned()
        }
        // W6 (Bug D): a METHOD call has its declared return type — lets a
        // template argument deduce from a member-call result. OWL EDITVIEW.CPP
        // `TEditView::VnCommit` does `ToBool(outStream->good())`; `good()` is
        // declared on `ios`, a shared VIRTUAL base of `ostream`, so the lookup
        // walks the full inheritance graph (`base` + `extra_bases` + `vbases`)
        // for a `Tag::name` entry in `fn_rets` (header inlines are
        // `Item::Func`s named `Tag::method`, registered at monomorphize start
        // — before the S4.2q reachability prune). Without this the argument
        // was un-typeable, `T` undeducible, and VnCommit deferred + dropped
        // (an unresolved external in the all-mdbcc OWL link).
        Expr::MethodCall { recv, name, .. } => {
            let rid = match type_of_expr(recv, scope, tcx)? {
                Type::Record { id, .. } => id,
                Type::Ptr(inner) | Type::Ref(inner) => match *inner {
                    Type::Record { id, .. } => id,
                    _ => return None,
                },
                _ => return None,
            };
            method_ret(rid, name, tcx)
        }
        // S4 (#27): an ARITHMETIC binary expression has the (promoted) type of its
        // operands — `sz - offset` is `unsigned`. Typing it lets a template
        // argument deduce from a computed expression, not just a bare variable:
        // CLASSLIB VECTIMP.H's `Resize` calls `min( sz-offset, Lim )`, where `Lim`
        // is a member (untypeable here) so `T` must come from `sz-offset`. Without
        // this, both args were skipped and `min`'s `T` was undeducible, deferring
        // `TVectorImpBase::Resize`. Relational/logical ops yield `int` (a bool-ish
        // result), not the operand type, so they are left to the `_` arm — a
        // comparison is never a sensible `min<T>` argument anyway.
        Expr::Binary {
            op:
                BinOp::Add
                | BinOp::Sub
                | BinOp::Mul
                | BinOp::Div
                | BinOp::Mod
                | BinOp::Shl
                | BinOp::Shr
                | BinOp::BitAnd
                | BinOp::BitOr
                | BinOp::BitXor,
            lhs,
            rhs,
            ..
        } => type_of_expr(lhs, scope, tcx).or_else(|| type_of_expr(rhs, scope, tcx)),
        // S6 (#28): a RELATIONAL / LOGICAL binary expression has type `int` (C's
        // "comparison yields int" rule — codegen's `expr_type` agrees). Typing it
        // lets a template argument deduce from a comparison result — OWL's
        // pervasive `ToBool<T>(x != y)` (geometry `TPoint::operator!=`, the
        // `IsXxx`/`TestFlag` accessors) deduces `T = int` from the `!=`. Without
        // this the sole argument was un-typeable, `T` was undeducible, and every
        // inline calling `ToBool` was deferred + dropped — leaving
        // `TPoint::operator!=`/`TSize::operator!=`/`TRect::Contains` and friends
        // unresolved across the whole OWL link.
        Expr::Binary {
            op:
                BinOp::Lt
                | BinOp::Le
                | BinOp::Gt
                | BinOp::Ge
                | BinOp::Eq
                | BinOp::Ne
                | BinOp::LAnd
                | BinOp::LOr,
            ..
        } => Some(Type::Int {
            bytes: 4,
            signed: true,
        }),
        _ => None,
    }
}

/// W6 (Bug D): the declared return type of method `name` on record `id` or
/// any class it inherits from — a BFS over `base` + `extra_bases` + `vbases`
/// (the vbase edge is what reaches `ios::good` through the iostream diamond),
/// most-derived first so an override's return type shadows its base's.
/// `fn_rets` is first-wins per name, so an overloaded method deduces from the
/// first-seen overload — fine for deduction (today these sites hard-defer).
fn method_ret(id: usize, name: &str, tcx: &Tcx) -> Option<Type> {
    let mut seen = HashSet::new();
    let mut work = std::collections::VecDeque::from([id]);
    while let Some(id) = work.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let Some(r) = tcx.records.get(id) else {
            continue;
        };
        if let Some(tag) = r.tag.as_deref()
            && let Some(t) = tcx.fn_rets.get(&format!("{tag}::{name}"))
        {
            return Some(t.clone());
        }
        if let Some(b) = r.base {
            work.push_back(b);
        }
        work.extend(r.extra_bases.iter().map(|b| b.id));
        work.extend(r.vbases.iter().map(|v| v.id));
    }
    None
}

/// Deduce the template's type arguments (in `params` order) from a call's
/// argument expressions. Only parameters that are *directly* a template
/// parameter contribute; every template parameter must be deduced, and a
/// parameter deduced twice must agree.
fn deduce(
    t: &TemplateDecl,
    args: &[Expr],
    scope: &HashMap<String, Type>,
    tcx: &Tcx,
) -> Result<Vec<Type>, CodegenError> {
    let mut map: HashMap<String, Type> = HashMap::new();
    for ((_, pty), arg) in t.func.params.iter().zip(args.iter()) {
        // S4.2b14 (was b12, re-landed on correct ref codegen — S4.2b13): a
        // parameter contributes a deduction whenever a template parameter appears
        // ANYWHERE in its type — directly (`T`) OR through a reference / pointer
        // (`const T&`, `T*`). The RTL's `min`/`max` (`const T& min(const T&,const
        // T&)`) take T by reference; the prior flat `if let TemplateParam` matched
        // only the direct form, so a ref-param template failed deduction and the
        // whole TU errored. `unify` walks `pty` against the argument's type,
        // binding each `T` (a reference binds to the argument's value type). Safe
        // only now that ref returns codegen correctly (b13) — before that, an
        // instantiated ref template silently miscompiled.
        if !contains_template_param(pty) {
            continue;
        }
        // S4.2b16: SKIP an argument whose static type we can't determine here
        // (e.g. `min(orig, s.length())` — `s.length()` is a method call, which
        // `type_of_expr` doesn't type) rather than erroring. A template parameter
        // need only be deducible from SOME argument; here `T` is deduced from
        // `orig`, so the unknown second argument is harmless. The final
        // every-parameter-deduced check below still rejects a genuinely
        // undeducible template. (Before, this hard error deferred+dropped the RTL
        // `string::assign`, leaving `@string@assign$q…` unresolved at link.)
        let Some(aty) = type_of_expr(arg, scope, tcx) else {
            continue;
        };
        unify(pty, &aty, &mut map, &t.func.name)?;
    }
    t.params
        .iter()
        .map(|p| {
            map.get(p).cloned().ok_or_else(|| {
                CodegenError(format!(
                    "template argument '{p}' of '{}' could not be deduced",
                    t.func.name
                ))
            })
        })
        .collect()
}

/// S4.2b14: does a template parameter appear anywhere in `t` (directly, or under
/// a reference / pointer / array)? Such a parameter contributes to deduction.
fn contains_template_param(t: &Type) -> bool {
    match t {
        Type::TemplateParam(_) => true,
        Type::Ref(i) | Type::Ptr(i) | Type::Array(i, _) => contains_template_param(i),
        _ => false,
    }
}

/// S4.2b14: unify a (possibly reference/pointer-wrapped) parameter type `pty`
/// against a call argument's value type `aty`, binding each `TemplateParam` in
/// `map`. A reference parameter (`const T&`) binds to the argument's VALUE type
/// (the argument expression's type carries no reference), so the referent is
/// unified directly against `aty`; a pointer/array parameter peels one level.
fn unify(
    pty: &Type,
    aty: &Type,
    map: &mut HashMap<String, Type>,
    fname: &str,
) -> Result<(), CodegenError> {
    match pty {
        Type::TemplateParam(name) => {
            if let Some(prev) = map.get(name) {
                if prev != aty {
                    return Err(CodegenError(format!(
                        "conflicting deductions for template argument '{name}' of '{fname}'"
                    )));
                }
            } else {
                map.insert(name.clone(), aty.clone());
            }
        }
        Type::Ref(inner) => unify(inner, aty, map, fname)?,
        Type::Ptr(inner) => {
            if let Type::Ptr(ainner) = aty {
                unify(inner, ainner, map, fname)?;
            }
        }
        Type::Array(inner, _) => match aty {
            Type::Array(ainner, _) | Type::Ptr(ainner) => unify(inner, ainner, map, fname)?,
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

/// The instantiation's symbol: `<name>$<borland-type-code…>` — deterministic
/// and unique per type-argument set (e.g. `maxv$i` for `maxv<int>`). A plain
/// non-overloaded in-TU function name, so def + call resolve identically.
fn mangle(name: &str, type_args: &[Type]) -> String {
    let mut s = format!("{name}$");
    for t in type_args {
        s.push_str(&borland_mangle_type(t));
    }
    s
}

/// Build a concrete [`Function`] from a template + deduced type arguments:
/// clone, substitute every `TemplateParam` in the signature and body, rename.
fn instantiate(t: &TemplateDecl, type_args: &[Type], sym: String, tcx: &Tcx) -> Function {
    let map: HashMap<String, Type> = t
        .params
        .iter()
        .cloned()
        .zip(type_args.iter().cloned())
        .collect();
    let mut f = t.func.clone();
    f.name = sym;
    f.ret = subst_type(&f.ret, &map, tcx);
    for (_, pty) in f.params.iter_mut() {
        *pty = subst_type(pty, &map, tcx);
    }
    subst_stmts(&mut f.body, &map, tcx);
    f
}

fn subst_type(t: &Type, map: &HashMap<String, Type>, tcx: &Tcx) -> Type {
    match t {
        Type::TemplateParam(name) => {
            // G13: a DEPENDENT nested type `Base::Inner` (the parser keeps the
            // qualifier). Once `Base` is bound to a concrete record, resolve the
            // nested record via the scoped `<tag>::Inner` key (#64). C++ name
            // lookup also finds nested types inherited from base classes; OWL's
            // `WriteBaseObject<TLayoutWindow>` relies on `TLayoutWindow::Streamer`
            // resolving to `TWindow::Streamer`.
            if let Some((base, nested_name)) = name.split_once("::")
                && let Some(Type::Record { id, .. }) = map.get(base)
                && let Some(nid) = resolve_nested_type(*id, nested_name, tcx)
                && let Some(r) = tcx.records.get(nid)
            {
                return Type::Record {
                    id: nid,
                    size: r.size,
                    align: r.align,
                };
            }
            // Direct parameter, or an unresolved dependent type (kept as-is so
            // codegen errors cleanly at any genuine use, never mis-resolves).
            map.get(name).cloned().unwrap_or_else(|| t.clone())
        }
        Type::Ptr(i) => Type::Ptr(Box::new(subst_type(i, map, tcx))),
        Type::Ref(i) => Type::Ref(Box::new(subst_type(i, map, tcx))),
        Type::Array(e, n) => Type::Array(Box::new(subst_type(e, map, tcx)), *n),
        Type::Func { ret, params } => Type::Func {
            ret: Box::new(subst_type(ret, map, tcx)),
            params: params.iter().map(|p| subst_type(p, map, tcx)).collect(),
        },
        Type::MemFn {
            class_id,
            ret,
            params,
        } => Type::MemFn {
            class_id: *class_id,
            ret: Box::new(subst_type(ret, map, tcx)),
            params: params.iter().map(|p| subst_type(p, map, tcx)).collect(),
        },
        other => other.clone(),
    }
}

fn resolve_nested_type(base_id: usize, nested_name: &str, tcx: &Tcx) -> Option<usize> {
    let mut seen = HashSet::new();
    let mut work = std::collections::VecDeque::from([base_id]);
    while let Some(id) = work.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let Some(r) = tcx.records.get(id) else {
            continue;
        };
        if let Some(tag) = r.tag.as_deref()
            && let Some(&nid) = tcx.nested.get(&format!("{tag}::{nested_name}"))
        {
            return Some(nid);
        }
        if let Some(b) = r.base {
            work.push_back(b);
        }
        work.extend(r.extra_bases.iter().map(|b| b.id));
        work.extend(r.vbases.iter().map(|v| v.id));
    }
    None
}

/// Substitute template parameters in the types embedded in a statement list
/// (local declaration types, cast / new / sizeof types), recursing into
/// nested control flow. Expression *values* are unchanged; only `Type` nodes
/// are rewritten.
fn subst_stmts(stmts: &mut [Stmt], map: &HashMap<String, Type>, tcx: &Tcx) {
    for s in stmts {
        match s {
            Stmt::Decl { ty, init, .. } => {
                *ty = subst_type(ty, map, tcx);
                if let Some(e) = init {
                    subst_expr(e, map, tcx);
                }
            }
            Stmt::Return(Some(e), _)
            | Stmt::ExprStmt(e, _)
            | Stmt::RefBindMember { rhs: e, .. } => subst_expr(e, map, tcx),
            Stmt::Block(b, _) => subst_stmts(b, map, tcx),
            Stmt::If {
                cond, then, els, ..
            } => {
                subst_expr(cond, map, tcx);
                subst_stmts(std::slice::from_mut(then), map, tcx);
                if let Some(e) = els {
                    subst_stmts(std::slice::from_mut(e), map, tcx);
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                subst_expr(cond, map, tcx);
                subst_stmts(std::slice::from_mut(body), map, tcx);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
                ..
            } => {
                if let Some(i) = init {
                    subst_stmts(std::slice::from_mut(i), map, tcx);
                }
                if let Some(c) = cond {
                    subst_expr(c, map, tcx);
                }
                if let Some(st) = step {
                    subst_expr(st, map, tcx);
                }
                subst_stmts(std::slice::from_mut(body), map, tcx);
            }
            Stmt::Switch {
                scrutinee, body, ..
            } => {
                subst_expr(scrutinee, map, tcx);
                subst_stmts(std::slice::from_mut(body), map, tcx);
            }
            Stmt::Case { value, .. } => subst_expr(value, map, tcx),
            _ => {}
        }
    }
}

fn subst_expr(e: &mut Expr, map: &HashMap<String, Type>, tcx: &Tcx) {
    match e {
        Expr::Cast { ty, expr } => {
            *ty = subst_type(ty, map, tcx);
            subst_expr(expr, map, tcx);
        }
        Expr::New {
            ty,
            args,
            placement,
        } => {
            *ty = subst_type(ty, map, tcx);
            for a in args.iter_mut().chain(placement.iter_mut()) {
                subst_expr(a, map, tcx);
            }
        }
        Expr::NewArray {
            ty,
            count,
            placement,
            ..
        } => {
            *ty = subst_type(ty, map, tcx);
            subst_expr(count, map, tcx);
            for a in placement {
                subst_expr(a, map, tcx);
            }
        }
        Expr::SizeofType(ty) => *ty = subst_type(ty, map, tcx),
        Expr::SizeofExpr(x) | Expr::Unary { expr: x, .. } | Expr::IncDec { target: x, .. } => {
            subst_expr(x, map, tcx)
        }
        Expr::Binary { lhs, rhs, .. } | Expr::Assign { lhs, rhs, .. } => {
            subst_expr(lhs, map, tcx);
            subst_expr(rhs, map, tcx);
        }
        Expr::Index { base, idx, .. } => {
            subst_expr(base, map, tcx);
            subst_expr(idx, map, tcx);
        }
        Expr::Cond { cond, then, els } => {
            subst_expr(cond, map, tcx);
            subst_expr(then, map, tcx);
            subst_expr(els, map, tcx);
        }
        Expr::Call { args, .. } => {
            for a in args {
                subst_expr(a, map, tcx);
            }
        }
        Expr::MethodCall {
            recv, name, args, ..
        } => {
            subst_expr(recv, map, tcx);
            for a in args.iter_mut() {
                subst_expr(a, map, tcx);
            }
            // G13: resolve a dependent-ctor sentinel (`$depctor$Base::Inner`,
            // emitted by the parser for `Base::Inner n(args)`) to the concrete
            // nested record's ctor tag, now that `Base` is bound. If the
            // dependent type still can't be resolved the sentinel is left in
            // place and codegen errors cleanly (never a silent miscompile).
            if let Some(dep) = name.strip_prefix("$depctor$")
                && let Type::Record { id, .. } =
                    subst_type(&Type::TemplateParam(dep.to_string()), map, tcx)
                && let Some(tag) = tcx.records.get(id).and_then(|r| r.tag.clone())
            {
                *name = tag;
            }
        }
        _ => {}
    }
}

/// Rewrite every template call in a statement list to its monomorphised name,
/// collecting any not-yet-created instantiations into `new_funcs`.
fn rewrite_stmts(
    stmts: &mut [Stmt],
    templates: &HashMap<String, Vec<TemplateDecl>>,
    scope: &HashMap<String, Type>,
    created: &mut HashSet<String>,
    new_funcs: &mut Vec<Function>,
    tcx: &Tcx,
) -> Result<(), CodegenError> {
    for s in stmts {
        match s {
            Stmt::Return(Some(e), _)
            | Stmt::ExprStmt(e, _)
            | Stmt::RefBindMember { rhs: e, .. } => {
                rewrite_expr(e, templates, scope, created, new_funcs, tcx)?
            }
            Stmt::Decl { init: Some(e), .. } => {
                rewrite_expr(e, templates, scope, created, new_funcs, tcx)?
            }
            Stmt::Block(b, _) => rewrite_stmts(b, templates, scope, created, new_funcs, tcx)?,
            Stmt::If {
                cond, then, els, ..
            } => {
                rewrite_expr(cond, templates, scope, created, new_funcs, tcx)?;
                rewrite_stmts(
                    std::slice::from_mut(then),
                    templates,
                    scope,
                    created,
                    new_funcs,
                    tcx,
                )?;
                if let Some(e) = els {
                    rewrite_stmts(
                        std::slice::from_mut(e),
                        templates,
                        scope,
                        created,
                        new_funcs,
                        tcx,
                    )?;
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                rewrite_expr(cond, templates, scope, created, new_funcs, tcx)?;
                rewrite_stmts(
                    std::slice::from_mut(body),
                    templates,
                    scope,
                    created,
                    new_funcs,
                    tcx,
                )?;
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
                ..
            } => {
                if let Some(i) = init {
                    rewrite_stmts(
                        std::slice::from_mut(i),
                        templates,
                        scope,
                        created,
                        new_funcs,
                        tcx,
                    )?;
                }
                if let Some(c) = cond {
                    rewrite_expr(c, templates, scope, created, new_funcs, tcx)?;
                }
                if let Some(st) = step {
                    rewrite_expr(st, templates, scope, created, new_funcs, tcx)?;
                }
                rewrite_stmts(
                    std::slice::from_mut(body),
                    templates,
                    scope,
                    created,
                    new_funcs,
                    tcx,
                )?;
            }
            Stmt::Switch {
                scrutinee, body, ..
            } => {
                rewrite_expr(scrutinee, templates, scope, created, new_funcs, tcx)?;
                rewrite_stmts(
                    std::slice::from_mut(body),
                    templates,
                    scope,
                    created,
                    new_funcs,
                    tcx,
                )?;
            }
            Stmt::Case { value, .. } => {
                rewrite_expr(value, templates, scope, created, new_funcs, tcx)?
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_expr(
    e: &mut Expr,
    templates: &HashMap<String, Vec<TemplateDecl>>,
    scope: &HashMap<String, Type>,
    created: &mut HashSet<String>,
    new_funcs: &mut Vec<Function>,
    tcx: &Tcx,
) -> Result<(), CodegenError> {
    // Rewrite nested sub-expressions first (arguments may themselves be
    // template calls).
    match e {
        Expr::Unary { expr: x, .. }
        | Expr::IncDec { target: x, .. }
        | Expr::Cast { expr: x, .. }
        | Expr::SizeofExpr(x) => rewrite_expr(x, templates, scope, created, new_funcs, tcx)?,
        Expr::Binary { lhs, rhs, .. } | Expr::Assign { lhs, rhs, .. } => {
            rewrite_expr(lhs, templates, scope, created, new_funcs, tcx)?;
            rewrite_expr(rhs, templates, scope, created, new_funcs, tcx)?;
        }
        Expr::Index { base, idx, .. } => {
            rewrite_expr(base, templates, scope, created, new_funcs, tcx)?;
            rewrite_expr(idx, templates, scope, created, new_funcs, tcx)?;
        }
        Expr::Cond { cond, then, els } => {
            rewrite_expr(cond, templates, scope, created, new_funcs, tcx)?;
            rewrite_expr(then, templates, scope, created, new_funcs, tcx)?;
            rewrite_expr(els, templates, scope, created, new_funcs, tcx)?;
        }
        Expr::Member { base, .. } => rewrite_expr(base, templates, scope, created, new_funcs, tcx)?,
        // A template call nested in a METHOD-call argument list must also be
        // rewritten (RTL string TUs: `p->splice(pos, min(n1, length()-pos), …)`
        // — without this arm the leftover `Expr::Call{"min"}` reached codegen
        // after fn_templates was cleared and fell out as a bare undefined
        // extern). Mirrors `subst_expr`'s MethodCall handling.
        Expr::MethodCall { recv, args, .. } => {
            rewrite_expr(recv, templates, scope, created, new_funcs, tcx)?;
            for a in args.iter_mut() {
                rewrite_expr(a, templates, scope, created, new_funcs, tcx)?;
            }
        }
        Expr::Call { name, args, .. } => {
            for a in args.iter_mut() {
                rewrite_expr(a, templates, scope, created, new_funcs, tcx)?;
            }
            // Only an arity-MATCHING overload instantiates the template. A plain
            // `new X` lowers to `operator new(size)` (1 arg); it must NOT bind to
            // the 2-parameter placement template `operator new(size_t, const
            // Alloc&)` (CLASSLIB's BIDS allocators) — that call resolves to the
            // ordinary global `operator new`. Arity is the cheap, correct
            // discriminator (S4.1b has no default args / packs in deduction), and
            // it also selects among same-name overloads (STDTEMPL.H `min(T,T)` vs
            // `min(T,T,T)`).
            if let Some(t) = templates
                .get(name)
                .and_then(|cands| cands.iter().find(|t| t.func.params.len() == args.len()))
            {
                let type_args = deduce(t, args, scope, tcx)?;
                let sym = mangle(name, &type_args);
                if created.insert(sym.clone()) {
                    new_funcs.push(instantiate(t, &type_args, sym.clone(), tcx));
                }
                *name = sym;
            }
        }
        _ => {}
    }
    Ok(())
}
