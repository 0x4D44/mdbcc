/* STDARG.H — MDBCC Win64 RTL varargs overlay (prepended to -I for every -m64 TU).
 *
 * BC4.52's <stdarg.h> implements va_start/va_arg/va_end as 16/32-bit STACK-WALKING
 * MACROS (va_start(ap,p)= &p+size; va_arg(ap,T)= *(T*)((ap+=size)-size)). On Win64
 * the first four args arrive in REGISTERS, not on the stack after the named params,
 * so those macros read garbage (RailC FINISH dialog: sprintf "%d" of a 0 field
 * printed a heap address). mdbcc's OWN va_arg/va_start are Win64-correct compiler
 * INTRINSICS (recognised by the parser), so this overlay keeps everything BC45's
 * header provides — `typedef void *va_list`, the `__size` rounding macro, `_va_ptr`
 * — EXCEPT the three va_* macros, leaving `va_start`/`va_arg`/`va_end` to reach the
 * parser as intrinsics. This lets the RTL printf core (`__vprinter`) walk the
 * register-spilled va_list correctly, while RTL code that does manual va_list
 * arithmetic with `__size` (e.g. REALCVT.C's `_nextreal`, advancing by 8 per double
 * — consistent with the intrinsic's fixed 8-byte slot) still compiles unchanged.
 * Win64-only: the overlay dir is prepended only for -m64; the i386 slice keeps BC45's
 * correct-for-32-bit macros (mdbcc's intrinsic va_arg has a separate i386 gap).
 */
#ifndef __STDARG_H
#define __STDARG_H

#ifdef __VARARGS_H
#error Can't include both STDARG.H and VARARGS.H
#endif

#if !defined(___DEFS_H)
#include <_defs.h>
#endif

typedef void _FAR *va_list;

#define __size(x) ((sizeof(x)+sizeof(int)-1) & ~(sizeof(int)-1))

/* va_start / va_arg / va_end are mdbcc Win64 compiler intrinsics — NOT macros. */

#if !__STDC__
#define _va_ptr             (...)
#endif

#define MDBCC_WIN64_OVERLAY_STDARG 1

#endif /* __STDARG_H */
