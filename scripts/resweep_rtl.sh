#!/bin/bash
# W2/W6: sweep-compile the Borland RTL + BIDS (CLASSLIB) sources with the
# CURRENT mdbcc into wrk_oracle/{rtl_objs,bids_objs}, then rebuild
# wrk_oracle/{mdcw32.lib,mdbids.lib}. Every TU that compiles cleanly lands;
# failures are skipped (counted) — the link-closure oracle (closure.sh)
# decides whether coverage suffices. Naming:
#   depth-3  RTL/SOURCE/<CAT>/<SUB>/<FILE>.<EXT> -> <CAT>_<SUB>_<FILE>.<EXT>.o
#   depth-2  RTL/SOURCE/<CAT>/<FILE>.<EXT>       -> <CAT>__<FILE>.<EXT>.o
#   BIDS     CLASSLIB/<FILE>.CPP                 -> <FILE>.o
# The shim objects (rtlshim.o / rtlio.o, wrk_rtlshim/) are rebuilt too — they
# carry the libc/float-format surface (__xcvt et al.) the RTL sweep can't
# self-host yet.
#
# Bug E (W6): TUs that `#define INCL_USER` before <ntbc.h> are uncompilable
# against the shipped 1994 headers at the WINDEF.H default WINVER=0x0400
# (winuser.h's 0x0400 block references LOGFONTA without wingdi.h — the bcc32
# ORACLE rejects the same line). Compile the two needed ones (ERRORMSG.C for
# _ErrorExit, GP.C for __DefHandler) with -DWINVER=0x030A, oracle-validated.
# The other INCL_USER TUs (GETCH/KBHIT/DEFHANDL/LOADPROG/STARTUP*) stay
# excluded: DEFHANDL would duplicate GP.C's __DefHandler, STARTUP* would
# fight mdbcc's own entry stub, and nothing references the rest.
#
# EASYWIN (W6): excluded entirely. It is a STARTUP VARIANT (Borland's
# console-on-a-window emulator, selected by `bcc -W` for "EasyWin" apps),
# not general RTL: EASYWIN.CPP defines `_hInstance` (duplicating the shim's)
# plus a whole fake-console window-proc, and pulls conio/Global* machinery
# into any image that touches it. A real OWL GUI app (railc) must never
# link it.
set -u
BCC=C:/language/mdbcc/target/release/bcc.exe
MDAR=C:/language/mdbcc/target/release/mdar.exe
RTLSRC=C:/tmp/bc45/SOURCE/RTL/SOURCE
BIDSSRC=C:/tmp/bc45/SOURCE/CLASSLIB
RTLOBJ=C:/language/mdbcc/wrk_oracle/rtl_objs
BIDSOBJ=C:/language/mdbcc/wrk_oracle/bids_objs
SINC="-I C:/tmp/bc45/INCLUDE -I C:/tmp/bc45/SOURCE/RTL/RTLINC/COMMON32 -I C:/tmp/bc45/SOURCE/RTL/RTLINC/WIN32 -I C:/tmp/bc45/SOURCE/RTL/RTLINC"
INC="-I C:/tmp/bc45/INCLUDE"

rm -rf "$RTLOBJ" "$BIDSOBJ"
mkdir -p "$RTLOBJ" "$BIDSOBJ"

rtl_ok=0; rtl_skip=0
compile_rtl() { # $1 = source path, $2 = object name, $3.. = extra flags
    local src=$1 obj=$2; shift 2
    if $BCC -c -m32 -D__WIN32__ "$@" $SINC "$src" -o "$RTLOBJ/$obj" >/dev/null 2>&1; then
        rtl_ok=$((rtl_ok+1))
    else
        rm -f "$RTLOBJ/$obj"
        rtl_skip=$((rtl_skip+1))
    fi
}

echo "=== RTL depth-3 (CAT/SUB) ==="
for cat in "$RTLSRC"/*/; do
    catname=$(basename "$cat")
    for sub in COMMON32 WIN32 WINDOWS; do
        [ -d "$cat$sub" ] || continue
        for src in "$cat$sub"/*.C "$cat$sub"/*.CPP; do
            [ -f "$src" ] || continue
            base=$(basename "$src")
            compile_rtl "$src" "${catname}_${sub}_${base}.o"
        done
    done
done

echo "=== RTL depth-2 (CAT direct children) ==="
for cat in "$RTLSRC"/*/; do
    catname=$(basename "$cat")
    [ "$catname" = "EASYWIN" ] && continue # startup variant, see header
    for src in "$cat"*.C "$cat"*.CPP; do
        [ -f "$src" ] || continue
        base=$(basename "$src")
        compile_rtl "$src" "${catname}__${base}.o"
    done
done

echo "=== Bug E: INCL_USER TUs at -DWINVER=0x030A ==="
compile_rtl "$RTLSRC/MISC/WIN32/ERRORMSG.C" "MISC_WIN32_ERRORMSG.C.o" -DWINVER=0x030A
compile_rtl "$RTLSRC/MISC/WIN32/GP.C" "MISC_WIN32_GP.C.o" -DWINVER=0x030A

echo "=== rtlshim ==="
$BCC -c -m32 -D__WIN32__ $INC C:/language/mdbcc/wrk_rtlshim/rtlshim.c -o "$RTLOBJ/rtlshim.o" || exit 1
$BCC -c -m32 -D__WIN32__ $SINC C:/language/mdbcc/wrk_rtlshim/rtlio.c -o "$RTLOBJ/rtlio.o" || exit 1

echo "rtl ok=$rtl_ok skip=$rtl_skip"

echo "=== BIDS (CLASSLIB) ==="
bids_ok=0; bids_skip=0
for src in "$BIDSSRC"/*.CPP; do
    base=$(basename "$src" .CPP)
    if $BCC -c -m32 -D__WIN32__ $INC "$src" -o "$BIDSOBJ/$base.o" >/dev/null 2>&1; then
        bids_ok=$((bids_ok+1))
    else
        rm -f "$BIDSOBJ/$base.o"
        bids_skip=$((bids_skip+1))
    fi
done
echo "bids ok=$bids_ok skip=$bids_skip"

echo "=== archives ==="
# Relative paths from inside the obj dirs — ~600 absolute paths overflow the
# Windows 32K command-line limit ("Argument list too long").
(cd "$RTLOBJ" && $MDAR -o C:/language/mdbcc/wrk_oracle/mdcw32.lib *.o) || exit 1
(cd "$BIDSOBJ" && $MDAR -o C:/language/mdbcc/wrk_oracle/mdbids.lib *.o) || exit 1
echo done
