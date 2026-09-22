use crate::ast::{Expr, Loc, Stmt, Type};

pub(super) fn static_local_symbol(func: &str, vname: &str, loc: Loc) -> String {
    format!(".slocal.{func}.{}.{}.{vname}", loc.line, loc.col)
}

pub(super) fn static_guard_symbol(func: &str, vname: &str, loc: Loc) -> String {
    format!(".sguard.{func}.{}.{}.{vname}", loc.line, loc.col)
}

/// Synthetic static-local key for a runtime-init static local's guard int.
/// The leading `\u{1}` cannot collide with a real C identifier, so the body's
/// `Expr::Var(static_guard_key(v, loc))` resolves only to the guard global
/// bound at that declaration site.
pub(super) fn static_guard_key(vname: &str, loc: Loc) -> String {
    format!("\u{1}sguard.{}.{}.{vname}", loc.line, loc.col)
}

/// S4.2o/B-17: collect every function-local `static` declaration (recursing
/// into nested blocks/loops/branches/handlers) as
/// `(name, type, optional init, declaration loc)`. Used to register one module
/// global per static-local declaration before pass 2.
pub(super) fn collect_static_locals<'a>(
    stmts: &'a [Stmt],
    out: &mut Vec<(&'a str, &'a Type, Option<&'a Expr>, Loc)>,
) {
    for s in stmts {
        match s {
            Stmt::Decl {
                name,
                ty,
                init,
                loc,
                is_static: true,
                ..
            } => {
                out.push((name, ty, init.as_ref(), *loc));
            }
            Stmt::Block(b, _) => collect_static_locals(b, out),
            Stmt::If { then, els, .. } => {
                collect_static_locals(std::slice::from_ref(then), out);
                if let Some(e) = els {
                    collect_static_locals(std::slice::from_ref(e), out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_static_locals(std::slice::from_ref(body), out)
            }
            Stmt::For { init, body, .. } => {
                if let Some(i) = init {
                    collect_static_locals(std::slice::from_ref(i), out);
                }
                collect_static_locals(std::slice::from_ref(body), out);
            }
            Stmt::Switch { body, .. } => collect_static_locals(std::slice::from_ref(body), out),
            Stmt::Try { body, catches, .. } => {
                collect_static_locals(body, out);
                for c in catches {
                    collect_static_locals(&c.body, out);
                }
            }
            _ => {}
        }
    }
}
