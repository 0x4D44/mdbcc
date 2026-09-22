/* wrk_rtlshim/rtlshim.c — mdbcc-built C reimplementations of the handful of
 * Borland RTL primitives that ship ONLY as hand-written 32-bit assembly
 * (RTL/SOURCE/CSTRINGS/COMMON32/{MEMMOVE,STRCHR,STRNCMP}.ASM, ...). mdbcc is a
 * C/C++ compiler and cannot assemble those, so to keep "every byte of railc.exe
 * mdbcc-built" (the GOAL) these few are provided here as plain, standard-
 * conforming C — behaviourally identical to the asm originals. This is NOT an
 * edit of the Borland oracle tree (C:/tmp/bc45/SOURCE); it is a separate,
 * mdbcc-compiled self-host shim, added to mdcw32.lib alongside the recompiled
 * RTL objects. Each function keeps C linkage (bare symbol) so it satisfies the
 * RTL/OWL callers' `memmove`/`strchr`/`strncmp` references exactly.
 *
 * The I/O syscall wrappers (open/read/write/lseek/close) live in rtlio.c
 * (reimplemented over Win32). The float-formatting boundary is BELOW: the
 * real converters are Borland C (REALCVT.C/XCVT.C, mdbcc-compiled, already in
 * mdcw32.lib) — only the 2-instruction CVTENTRY.ASM trampolines and the
 * `#pragma startup` init path needed shimming, so digit parity is inherited
 * from the same Borland source (proven by the bcc32 float-corpus diff).
 */

typedef unsigned int rtl_size_t; /* SIZE_T / size_t on Win32 (4 bytes) */

void *GetProcessHeap(void);
void *HeapAlloc(void *heap, unsigned flags, unsigned bytes);
int HeapFree(void *heap, unsigned flags, void *mem);

void *memmove(void *dest, const void *src, rtl_size_t n)
{
    char *d = (char *)dest;
    const char *s = (const char *)src;
    if (d == s || n == 0)
        return dest;
    if (d < s) {
        while (n--)
            *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--)
            *--d = *--s;
    }
    return dest;
}

/* MEMCHR.ASM — asm-only, like the rest of this family. Pulled into the
 * link once the G48 startup chain brought the stdio/scan RTL members in. */
void *memchr(const void *s, int c, rtl_size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    unsigned char ch = (unsigned char)c;
    while (n--) {
        if (*p == ch)
            return (void *)p;
        p++;
    }
    return 0;
}

char *strchr(const char *s, int c)
{
    char ch = (char)c;
    while (*s) {
        if (*s == ch)
            return (char *)s;
        s++;
    }
    /* The terminating NUL is part of the string for `strchr(s, 0)`. */
    return (ch == 0) ? (char *)s : (char *)0;
}

int strncmp(const char *a, const char *b, rtl_size_t n)
{
    while (n--) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca != cb)
            return (int)ca - (int)cb;
        if (ca == 0)
            return 0;
    }
    return 0;
}

int strcmp(const char *a, const char *b)
{
    /* STRCMP.ASM is asm-only on 32-bit — same shim treatment as memmove/
     * strchr/strncmp (W6 honest closure: OWL pulls it via the ctor thunks). */
    while (*a != 0 && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* --- native heap shim -------------------------------------------------------
 * Borland's COMMON32 HEAP.C is structurally 32-bit: free-list pointers are
 * stored at offsets 0 and 4 inside a block, so its startup initializer corrupts
 * itself on Win64 before RailC reaches WinMain. For the source-built native
 * path, satisfy the C allocation surface with the process heap instead. The
 * 16-byte prefix keeps returned pointers naturally aligned on Win64. The
 * stored size matches Borland's non-debug `_msize` contract: minimum 8 bytes,
 * rounded up to a 4-byte boundary.
 */
#define RTL_HEAP_PREFIX 16u
#define HEAP_ZERO_MEMORY 8u

struct rtl_heap_rec
{
    char *base;
    unsigned long len;
};

/* Some Borland RTL objects include _malloc.h and carry these externs even
 * without using the 32-bit heap manager. Defining the debug-facing globals here
 * keeps COMMON32/HEAP.C out of native Win64 links, so its pointer-truncating
 * startup initializer cannot run. */
struct rtl_heap_rec _heaps[64];
int _nheaps;

static int rtl_heap_usable_size(rtl_size_t size, unsigned *usable)
{
    unsigned rounded;
    if (size == 0)
        return 0;
    if (size < 8u) {
        rounded = 8u;
    } else {
        rounded = (size + 3u) & ~3u;
        if (rounded < size)
            return 0;
    }
    if (rounded > ~0u - RTL_HEAP_PREFIX)
        return 0;
    *usable = rounded;
    return 1;
}

void *malloc(rtl_size_t size)
{
    unsigned usable;
    unsigned *raw;
    if (!rtl_heap_usable_size(size, &usable))
        return 0;
    raw = (unsigned *)HeapAlloc(GetProcessHeap(), 0, usable + RTL_HEAP_PREFIX);
    if (raw == 0)
        return 0;
    raw[0] = usable;
    raw[1] = size;
    raw[2] = 0;
    raw[3] = 0;
    return (void *)((char *)raw + RTL_HEAP_PREFIX);
}

void free(void *ptr)
{
    if (ptr != 0)
        HeapFree(GetProcessHeap(), 0, (char *)ptr - RTL_HEAP_PREFIX);
}

void *calloc(rtl_size_t nelem, rtl_size_t elsize)
{
    unsigned bytes = nelem * elsize;
    unsigned *raw;
    unsigned usable;
    if (nelem != 0 && bytes / nelem != elsize)
        return 0;
    if (!rtl_heap_usable_size(bytes, &usable))
        return 0;
    raw = (unsigned *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, usable + RTL_HEAP_PREFIX);
    if (raw == 0)
        return 0;
    raw[0] = usable;
    raw[1] = bytes;
    return (void *)((char *)raw + RTL_HEAP_PREFIX);
}

void *_expand(void *ptr, rtl_size_t size)
{
    unsigned *raw;
    unsigned usable;
    if (ptr == 0 || size == 0)
        return 0;
    if (!rtl_heap_usable_size(size, &usable))
        return 0;
    raw = (unsigned *)((char *)ptr - RTL_HEAP_PREFIX);
    if (usable <= raw[0]) {
        raw[0] = usable;
        raw[1] = size;
        return ptr;
    }
    return 0;
}

void *realloc(void *ptr, rtl_size_t size)
{
    unsigned old_size;
    void *next;
    if (ptr == 0)
        return malloc(size);
    if (size == 0) {
        free(ptr);
        return 0;
    }
    if (_expand(ptr, size) != 0)
        return ptr;
    old_size = ((unsigned *)((char *)ptr - RTL_HEAP_PREFIX))[0];
    next = malloc(size);
    if (next != 0) {
        memmove(next, ptr, old_size < size ? old_size : size);
        free(ptr);
    }
    return next;
}

rtl_size_t _msize(void *ptr)
{
    if (ptr == 0)
        return 0;
    return ((unsigned *)((char *)ptr - RTL_HEAP_PREFIX))[0];
}

/* --- legacy CTL3D compatibility -------------------------------------------
 * Native Win64 Windows does not ship CTL3D32.DLL. RailC calls these three
 * functions directly at startup/shutdown for old 3D-control decoration; OWL
 * also has a dynamic LoadLibrary/GetProcAddress path that can safely see the
 * DLL as absent. For the source-built native path, make the direct calls
 * mdbcc-built no-op successes rather than a hard loader dependency on a
 * missing legacy DLL.
 */
int Ctl3dRegister(void *instance)
{
    (void)instance;
    return 1;
}

int Ctl3dAutoSubclass(void *instance)
{
    (void)instance;
    return 1;
}

int Ctl3dUnregister(void *instance)
{
    (void)instance;
    return 1;
}

/* --- float-conversion entries (RTL/SOURCE/MATH/COMMON32/CVTENTRY.ASM) ------
 * CVTENTRY.ASM defines __realcvt/__nextreal as 2-instruction trampolines
 * (`jmp [_realcvtptr]` / `jmp [_nextrealptr]`) through pointers defined in
 * CVTFAK.C (defaulting to a "floating point formats not linked" abort). The
 * REAL converters — static _realcvt/_nextreal in REALCVT.C — are installed by
 * _cvt_init(), normally run via `#pragma startup _cvt_init 10` (INITCVT.C),
 * force-linked by a compiler-emitted _turboFloat reference. mdbcc neither
 * emits _turboFloat refs nor honours #pragma startup, so the trampolines here
 * call _cvt_init() LAZILY (idempotent: two pointer stores) before
 * dispatching — guaranteeing the genuine Borland converters (mdbcc-compiled
 * REALCVT.C/XCVT.C/POW10*, already in mdcw32.lib) run, never _fakecvt.
 *
 * The extern pointers are declared with their CALLABLE signatures (CVTFAK.C
 * defines them as `void (*)(void)`) — only the SYMBOL matters at link, and
 * calling through the real type avoids function-pointer casts. Signatures
 * from _PRINTF.H:67-70; Borland Win32 va_list = void* (stdarg.h:27).
 */
typedef void *rtl_va_list;

extern void (*_realcvtptr)(void *valueP, int ndec, char *strP, char formCh,
                           char altFormat, int type);
extern rtl_va_list (*_nextrealptr)(rtl_va_list ap, int isLongDouble);
extern void _cvt_init(void); /* REALCVT.C */

void __realcvt(void *valueP, int ndec, char *strP, char formCh,
               char altFormat, int type)
{
    _cvt_init();
    _realcvtptr(valueP, ndec, strP, formCh, altFormat, type);
}

rtl_va_list __nextreal(rtl_va_list ap, int isLongDouble)
{
    _cvt_init();
    return _nextrealptr(ap, isLongDouble);
}

/* --- __xcvt (RTL/SOURCE/MATH/COMMON32/XCVT.C) -------------------------------
 * XCVT.C is written against the 80-bit x87 EXTENDED layout (`fracw[4]` reads
 * the exponent:sign word at byte offset 8, bias 0x3FFF, helpers _fxam/
 * _fuistq/_qdiv10 are x87 asm). mdbcc folds `long double` to `double`, so the
 * mdbcc-compiled XCVT.C object reads PAST its 8-byte local — silently broken;
 * it is EXCLUDED from mdcw32.lib and replaced by this EXACT reimplementation.
 *
 * Why exact: bcc32's pipeline (extended-precision 10^k scaling + fistp RTNE)
 * yields the CORRECTLY-ROUNDED decimal expansion of the double for every
 * digit count it can represent (<= MaxSigDigits 19, the extended mantissa's
 * exact-integer range), zero-padded beyond — verified across the whole
 * /tmp/fcorpus golden corpus. A double-based 10^k rescale could not match
 * that tail (and overflowed the 2^63 decompose for DBL_MAX), so the digit
 * core here generates the exact decimal digits of m*2^e with a 16-bit-limb
 * bignum: integer part by repeated divmod-10, fraction part by repeated *10
 * with the digit carried out across the 2^(16*dq) unit boundary. Round-to-
 * nearest-EVEN at the requested position (ties resolved on the exact tail,
 * matching fistp), then the XCVT.C roundup/pad tail verbatim. 32-bit-only
 * arithmetic — the i386 u64 paths are not oracle-proven (notes/2026.06.09).
 *
 * Contract (_PRINTF.H): fills strP with the significant-digit string (no
 * point), *signP = sign, returns the decimal exponent (digits left of the
 * point), INF_number 32767 / NAN_number 32766 for specials.
 */

/* Limb budgets: integer part DBL_MAX = m(53b)<<971 -> 1024 bits = 64 limbs
 * (+1 shift carry); fraction part denormal-min q = 1074 -> 68 limbs. The
 * full integer decimal expansion is at most 309 digits. */
#define XCVT_ILIMBS 68
#define XCVT_FLIMBS 70
#define XCVT_IDIGS 320

/* Full decimal expansion of the limb integer (little-endian limbs), MSD
 * first; returns the digit count (0 when the value is zero). Destroys l. */
static int xcvt_int_to_dec(unsigned short *l, int n, char *out)
{
    char rev[XCVT_IDIGS];
    int cnt = 0, i, top = n;
    while (top > 0 && l[top - 1] == 0)
        top--;
    while (top > 0) {
        unsigned r = 0;
        for (i = top - 1; i >= 0; i--) {
            unsigned t = (r << 16) | (unsigned)l[i];
            l[i] = (unsigned short)(t / 10u);
            r = t % 10u;
        }
        rev[cnt++] = (char)r;
        while (top > 0 && l[top - 1] == 0)
            top--;
    }
    for (i = 0; i < cnt; i++)
        out[i] = rev[cnt - 1 - i];
    return cnt;
}

/* Fraction value F/2^(16*dq) held in fl[0..dq): multiply by 10 in place and
 * return the integer digit that crosses the unit boundary (the carry out of
 * limb dq-1; F < 2^(16dq) so the digit is 0..9). */
static int xcvt_frac_mul10(unsigned short *fl, int dq)
{
    unsigned carry = 0;
    int i;
    for (i = 0; i < dq; i++) {
        unsigned t = (unsigned)fl[i] * 10u + carry;
        fl[i] = (unsigned short)(t & 0xFFFFu);
        carry = t >> 16;
    }
    return (int)carry;
}

static int xcvt_limbs_zero(const unsigned short *l, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (l[i])
            return 0;
    return 1;
}

int __xcvt(void *valP, int digits, int *signP, char *strP, int ftype)
{
    double frac;
    union {
        double d;
        unsigned w[2];
    } u;
    unsigned be, w1m, m7;
    unsigned short ml[4];
    unsigned short il[XCVT_ILIMBS];
    unsigned short fl[XCVT_FLIMBS];
    char ibuf[XCVT_IDIGS];
    char sig[24];
    long templ;
    int tempw, e_unbiased, est, diff;
    int e2, q, dq, sb, s16, i;
    int icnt, ipos, pend, decimals;
    int prec, ndigs, dnext, tail_nonzero, roundup_flag, len;
    char *p, *endp;

    if (ftype == 2) /* F_4byteFloat */
        frac = (double)*(float *)valP;
    else /* F_8byteFloat / F_10byteFloat (long double == double under mdbcc) */
        frac = *(double *)valP;

    u.d = frac;
    *signP = (int)(u.w[1] >> 31);
    u.w[1] &= 0x7FFFFFFFu; /* zap the sign bit (XCVT.C: fracw[4] &= 0x7fff) */
    frac = u.d;

    be = (u.w[1] >> 20) & 0x7FFu; /* biased exponent */
    if (be == 0x7FFu) {
        if ((u.w[1] & 0xFFFFFu) != 0u || u.w[0] != 0u)
            return 32766; /* NAN_number */
        return 32767;     /* INF_number */
    }
    if (frac == 0.0) {
    roundToZero:
        if ((ndigs = digits) <= 0)
            ndigs = -ndigs + 1; /* digit left of decimal point */
        if (ndigs > 40)         /* __XCVTDIG__: limit caller's buffer */
            ndigs = 40;
        for (p = strP; p < strP + ndigs; p++)
            *p = '0';
        strP[ndigs] = '\0';
        *signP = 0; /* eliminate negative zero */
        return 1;   /* We really want 0.0E+01 */
    }

    /* v = m * 2^e2 exactly: m = 53-bit mantissa (implicit bit for normals),
     * e2 = be - 1075 (denormals: be==0 acts as be==1, no implicit bit). */
    w1m = (u.w[1] & 0xFFFFFu) | (be != 0u ? 0x100000u : 0u);
    e2 = (be != 0u ? (int)be : 1) - 1075;
    ml[0] = (unsigned short)(u.w[0] & 0xFFFFu);
    ml[1] = (unsigned short)(u.w[0] >> 16);
    ml[2] = (unsigned short)(w1m & 0xFFFFu);
    ml[3] = (unsigned short)(w1m >> 16);

    /* Decimal-magnitude ESTIMATE — XCVT.C verbatim (binary exponent times
     * 10000h*Log10of2 in 16.16 fixed point + a high-mantissa correction).
     * bcc32 derives the digit-generation count AND the rounds-to-zero gate
     * from this estimate, then corrects by one after scaling; byte parity
     * requires driving prec from the SAME estimate, with the exact decimal
     * exponent (below) supplying the correction step. */
    e_unbiased = (int)be - 0x3FF;
    if (be == 0u) {
        u.d = u.d * 18446744073709551616.0; /* 2^64, exact (denormal view) */
        be = (u.w[1] >> 20) & 0x7FFu;
        e_unbiased = (int)be - 0x3FF - 64;
    }
    m7 = (u.w[1] >> 13) & 0x7Fu; /* top 7 mantissa bits */
    templ = (long)e_unbiased;
    templ *= 0x4D10L;
    tempw = (int)(((m7 << 1) & 0xFFu) * 0x4Du);
    templ += (long)tempw & 0xFFFFL;
    est = (int)(templ >> 16);
    if ((templ & 0xFFFFL) != 0)
        est++;

    if ((prec = digits) <= 0) {
        /* The caller has requested (-digits) decimals after the point —
         * gated on the ESTIMATE, exactly like XCVT.C. */
        if ((prec = est - digits) < 0)
            goto roundToZero;
    }
    if (prec > 19) /* MaxSigDigits */
        prec = 19;

    /* Exact split at the binary point. */
    for (i = 0; i < XCVT_ILIMBS; i++)
        il[i] = 0;
    for (i = 0; i < XCVT_FLIMBS; i++)
        fl[i] = 0;
    dq = 0;
    if (e2 >= 0) {
        /* Pure integer: il = m << e2. */
        unsigned carry = 0;
        s16 = e2 / 16;
        sb = e2 % 16;
        for (i = 0; i < 4; i++) {
            unsigned t = ((unsigned)ml[i] << sb) | carry;
            il[i + s16] = (unsigned short)(t & 0xFFFFu);
            carry = t >> 16;
        }
        il[4 + s16] = (unsigned short)carry;
    } else {
        /* T = m << sb places the fraction numerator (unit boundary at bit
         * 16*dq) in limbs [0,dq) and the integer part in the limbs above. */
        unsigned carry = 0;
        unsigned short tl[5];
        q = -e2;            /* v = m / 2^q, q <= 1074 */
        dq = (q + 15) / 16; /* fraction limbs */
        sb = 16 * dq - q;   /* 0..15 */
        for (i = 0; i < 4; i++) {
            unsigned t = ((unsigned)ml[i] << sb) | carry;
            tl[i] = (unsigned short)(t & 0xFFFFu);
            carry = t >> 16;
        }
        tl[4] = (unsigned short)carry;
        for (i = 0; i < 5; i++) {
            if (i < dq)
                fl[i] = tl[i];
            else
                il[i - dq] = tl[i];
        }
    }

    /* Exact decimal exponent + significant-digit stream (integer digits MSD
     * first, then fraction digits). */
    icnt = xcvt_int_to_dec(il, XCVT_ILIMBS, ibuf);
    ipos = 0;
    pend = -1;
    decimals = icnt;
    if (icnt == 0) {
        /* 0 < v < 1: skip leading zero fraction digits exactly. */
        for (;;) {
            int d = xcvt_frac_mul10(fl, dq);
            if (d != 0) {
                pend = d;
                break;
            }
            decimals--;
        }
    }

    /* XCVT.C's post-scale estimate correction, replayed exactly: F format
     * (digits <= 0) moves the rounding position with the exponent; E format
     * rescales back to the requested count — UNLESS that would exceed the
     * 19-digit cap (prec+1 > 19), where XCVT skips the rescale and emits the
     * extra digit. `diff` is the estimate error (never more than one). */
    diff = decimals - est;
    if (digits <= 0)
        prec += diff;
    else if (diff > 0 && prec + diff > 19)
        prec += diff;
    if (prec < 0)
        goto roundToZero;

    /* Collect prec exact significant digits, then the rounding digit. */
    for (i = 0; i < prec; i++) {
        if (pend >= 0) {
            sig[i] = (char)pend;
            pend = -1;
        } else if (ipos < icnt) {
            sig[i] = ibuf[ipos++];
        } else {
            sig[i] = (char)xcvt_frac_mul10(fl, dq);
        }
    }
    if (pend >= 0) {
        dnext = pend;
        pend = -1;
    } else if (ipos < icnt) {
        dnext = ibuf[ipos++];
    } else {
        dnext = xcvt_frac_mul10(fl, dq);
    }
    tail_nonzero = !xcvt_limbs_zero(fl, dq);
    for (i = ipos; i < icnt; i++) {
        if (ibuf[i] != 0) {
            tail_nonzero = 1;
            break;
        }
    }

    /* Round to nearest, ties to EVEN on the exact tail (fistp semantics). */
    roundup_flag = dnext > 5
        || (dnext == 5
            && (tail_nonzero || (prec > 0 && (sig[prec - 1] & 1) != 0)));

    if (prec == 0) {
        /* A fraction that may round up to exactly 1 at the cut. */
        if (!roundup_flag)
            goto roundToZero; /* rounded to 0: print as 0 */
        decimals++;
        strP[0] = '1';
        endp = &strP[1];
        goto pad;
    }

    len = prec;
    if (roundup_flag) {
        i = prec - 1;
        while (i >= 0 && sig[i] == 9) {
            sig[i] = 0;
            i--;
        }
        if (i >= 0) {
            sig[i]++;
        } else {
            /* 999.. rounded up to 1000..: XCVT.C's fixup — the string keeps
             * prec digits for E format (digits > 0) and grows by one for F
             * (digits <= 0); either way it is '1' then zeros. */
            decimals++;
            sig[0] = 1;
            for (i = 1; i < prec; i++)
                sig[i] = 0;
            if (digits <= 0) {
                sig[prec] = 0;
                len = prec + 1; /* the appended '0' */
            }
        }
    }
    for (i = 0; i < len; i++)
        strP[i] = (char)('0' + sig[i]);
    endp = &strP[len];

pad:
    /* Append zeros up to the intended length (cap __XCVTDIG__ = 40). */
    if ((ndigs = digits) <= 0)
        ndigs = decimals - digits;
    if (ndigs > 40)
        ndigs = 40;
    *endp = '\0';
    ndigs -= (int)(endp - strP);
    if (ndigs > 0) {
        for (p = endp; p < endp + ndigs; p++)
            *p = '0';
        *(endp + ndigs) = '\0';
    }
    return decimals;
}

/* --- C0 startup data (RTL/SOURCE/STARTUP/WIN32/C0NT.ASM) -------------------
 * C0NT.ASM: `__hInstance dd 0`, set at startup via GetModuleHandleA(NULL)
 * (EXE path, lines 337-339). mdlink's PE32 images are fixed-base
 * (IMAGE_BASE_PE32 = 0x00400000, pe_writer.rs) and RELOCS_STRIPPED, so the
 * module handle is statically 0x00400000 — the exact value the i386 GUI entry
 * stub already pushes as WinMain's hInstance. Declared `extern HINSTANCE
 * _hInstance` in INCLUDE/OSL/DEFS.H:106; OWL MODULE.CPP:122 reads it.
 * If the image base ever changes or .reloc/ASLR lands, update this constant.
 */
void *_hInstance = (void *)0x400000;

/* --- termination + runtime-error surface (STARTUP.C / C0NT.ASM) -----------
 * W6: pulled in once the revived inline ctors (G45) reference the CHECKS.CPP
 * precondition machinery (-> ERRORMSG.C `_ErrorExit`) and EXIT.C gets pulled
 * for `exit`. Their three startup-owned externs live in TUs we exclude:
 *
 *   `_cleanup`   (STARTUP.C:500) walks the `_EXIT_` init-record tables — the
 *                `#pragma exit` machinery. mdbcc images register NO such
 *                records (static dtors ride `atexit`, which EXIT.C's __exit
 *                runs itself before calling _cleanup), so the faithful shim
 *                is a no-op.
 *   `_terminate` (STARTUP.C:554) is `ExitProcess(code)` verbatim.
 *   `__isGUI`    (C0NT.ASM:201-210) is a LINK-TIME constant: `db 1` in the
 *                GUI startup object (C0W32, -DWINDOWS), `db 0` in the console
 *                one (C0X32). ERRORMSG.C's `_ErrorMessage` reads it to choose
 *                MessageBox vs stderr. mdbcc has ONE shim for both kinds of
 *                image, so compute the same answer at startup from the PE
 *                header's Subsystem field (IMAGE_SUBSYSTEM_WINDOWS_GUI == 2)
 *                via the dynamic-init fallback (#32) — "GUI startup object"
 *                if and only if "GUI subsystem image".
 */
void ExitProcess(unsigned int code);
void *GetModuleHandleA(const char *name);

void _cleanup(void)
{
}

void _terminate(int code)
{
    ExitProcess((unsigned int)code);
}

static unsigned char rtl_sniff_gui(void)
{
    const char *base = (const char *)GetModuleHandleA(0);
    int e_lfanew = *(const int *)(base + 0x3C);
    /* PE sig (4) + COFF header (20) = 24 to OptionalHeader; Subsystem at +68
     * (same offset in PE32 and PE32+). */
    unsigned short subsystem = *(const unsigned short *)(base + e_lfanew + 24 + 68);
    return subsystem == 2 ? 1 : 0;
}
unsigned char __isGUI = rtl_sniff_gui();

/* --- C0 startup data + seeding (STARTUP.C:55-66 / 390-396) ----------------
 * Storage for the startup globals the INIT chain reads, owned by STARTUP.C
 * in a Borland link (excluded here — it fights the mdbcc entry stub).
 * `_setargv` (#pragma startup 3) parses `_oscmd` into `_C0argc`/`_C0argv`;
 * `_setenvp` walks `_osenv` into `_C0environ`. The seeding STARTUP.C does
 * inline before the INIT chain (`_oscmd = GetCommandLine(); _osenv =
 * GetEnvironmentStrings();`) becomes a priority-0 `#pragma startup` here —
 * mdbcc runs startup records ascending, so the seed precedes _setargv(3).
 */
int _C0argc;
char **_C0argv;
char **_C0environ;
char *_oscmd;
char *_osenv;

char *GetCommandLineA(void);
char *GetEnvironmentStringsA(void);

static void rtl_c0_init(void)
{
    _oscmd = GetCommandLineA();
    _osenv = GetEnvironmentStringsA();
}
#pragma startup rtl_c0_init 0

/* --- x87 helpers shipped only as assembly ----------------------------------
 * `_control87` (CTRL87.ASM): read/merge/write the real x87 control word.
 * mdbcc provides the two private intrinsics below as raw `fnstcw`/`fldcw`
 * because full inline assembly would be a much larger feature than this shim
 * needs.
 */
unsigned __mdbcc_fnstcw(void);
void __mdbcc_fldcw(unsigned cw);

unsigned _control87(unsigned newcw, unsigned mask)
{
    unsigned cw = __mdbcc_fnstcw();
    cw = (cw & ~mask) | (newcw & mask);
    __mdbcc_fldcw(cw);
    return __mdbcc_fnstcw();
}

/* `_qmul10` (QMUL10.ASM): *quadint = *quadint * 10 + digit over a 64-bit
 * unsigned, returning non-zero on overflow out of bit 63. 16-bit halves
 * (u32 ops only — the i386 u64 paths stay quarantined, same discipline as
 * the __xcvt limb core). Helper for SCANTOD.C (strtod).
 */
int _qmul10(unsigned long *quadint, int digit)
{
    unsigned short *h = (unsigned short *)quadint;
    unsigned carry = (unsigned)digit;
    int i;
    for (i = 0; i < 4; i++) {
        unsigned v = (unsigned)h[i] * 10u + carry;
        h[i] = (unsigned short)v;
        carry = v >> 16;
    }
    return carry != 0;
}

/* `_fuildq` (FUILDQ.ASM): load a 64-bit UNSIGNED integer as a long double
 * for SCANTOD.C. The asm keeps all 64 mantissa bits in the 80-bit x87
 * format; mdbcc's `long double` is the 64-bit double, so values above 2^53
 * round to nearest-double here — the same precision profile every other
 * mdbcc-compiled `long double` expression already has. quadint halves are
 * combined via 2^32 scaling (exact in double).
 */
long double _fuildq(unsigned long *valP)
{
    return (long double)valP[1] * 4294967296.0 + (long double)valP[0];
}

/* `isatty` (ISATTY.ASM): the user-callable entry is a pure alias for
 * `__isatty` (`Entry@ isatty, __isatty`), which IS mdbcc-compiled from
 * IO/WIN32/__ISATTY.C. Forward.
 */
int __isatty(int handle);

int isatty(int handle)
{
    return __isatty(handle);
}

/* --- rand family (RTL/SOURCE/MATH/COMMON32/RAND.C) ------------------------
 * RAND.C is `#pragma inline`: `_lrand` is inline-asm-bodied, so the whole TU
 * needs an assembler. Reimplemented here, bug-for-bug with the SHIPPED asm:
 * the asm's 64-bit LCG multiplier is 0x000015A4_00004E35 (it splits 0x15A4 /
 * 0x4E35 across DWORD boundaries) — NOT the 0x015A4E35 the C comment claims.
 * `rand` does use 0x015A4E35 on Seed.lo only. All three share one seed state
 * (lo/hi), initial {1, 0}, exactly like RAND.C's `__seed_t Seed`.
 * 32-bit-only arithmetic (no u64): the i386 backend's 64-bit paths are not
 * oracle-proven yet, and the asm itself is 32-bit ops.
 */
static unsigned rtl_seed_lo = 1;
static unsigned rtl_seed_hi = 0;

void srand(unsigned seed)
{
    rtl_seed_lo = seed;
    rtl_seed_hi = 0;
}

int rand(void)
{
    rtl_seed_lo = 0x015A4E35u * rtl_seed_lo + 1;
    return (int)((rtl_seed_lo >> 16) & 0x7FFF);
}

long _lrand(void)
{
    unsigned lo = rtl_seed_lo;
    unsigned hi = rtl_seed_hi;
    /* bits 32..63 contribution, mod 2^32 (matches the asm's lost carries) */
    unsigned hipart = 0x15A4u * lo + 0x4E35u * hi;
    /* 32x15-bit product lo * 0x4E35 -> 48 bits, via 16-bit halves */
    unsigned l0 = lo & 0xFFFFu;
    unsigned l1 = lo >> 16;
    unsigned m0 = l0 * 0x4E35u; /* < 2^31 */
    unsigned m1 = l1 * 0x4E35u; /* < 2^31 */
    unsigned mid = (m0 >> 16) + (m1 & 0xFFFFu); /* < 2^17 */
    unsigned p_lo = (m0 & 0xFFFFu) | (mid << 16);
    unsigned p_hi = (m1 >> 16) + (mid >> 16);
    p_lo += 1u; /* INCREMENT, with carry into the high dword */
    if (p_lo == 0u)
        p_hi += 1u;
    p_hi += hipart;
    rtl_seed_lo = p_lo;
    rtl_seed_hi = p_hi;
    return (long)(p_hi & 0x7FFFFFFFu);
}
