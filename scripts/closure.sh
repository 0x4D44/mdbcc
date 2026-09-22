#!/bin/bash
set -u
BCC=C:/language/mdbcc/target/release/bcc.exe
MDAR=C:/language/mdbcc/target/release/mdar.exe
MDLINK=C:/language/mdbcc/target/release/mdlink.exe
RB=/tmp/rb
rm -rf $RB; mkdir -p $RB/railc $RB/owl $RB/streams
INC="-I C:/tmp/bc45/INCLUDE"
SINC="-I C:/tmp/bc45/INCLUDE -I C:/tmp/bc45/SOURCE/RTL/RTLINC/COMMON32 -I C:/tmp/bc45/SOURCE/RTL/RTLINC/WIN32"
STSRC="C:/tmp/bc45/SOURCE/RTL/SOURCE/IOSTREAM"
echo "=== railc ==="
rok=0
for f in C:/language/railc/*.CPP C:/language/railc/*.cpp; do b=$(basename "$f" .CPP); $BCC -c -m32 -D__WIN32__ -I C:/language/railc $INC "$f" -o "$RB/railc/$b.o" >/dev/null 2>&1 && rok=$((rok+1)); done
echo "railc ok=$rok"
echo "=== owl ==="
ook=0
for f in C:/tmp/bc45/SOURCE/OWL/*.CPP; do b=$(basename "$f" .CPP); $BCC -c -m32 -D__WIN32__ $INC "$f" -o "$RB/owl/$b.o" >/dev/null 2>&1 && ook=$((ook+1)); done
echo "owl ok=$ook"
echo "=== streams ==="
STF="IOFSCTR1 IOFSDTR FSCTR1 FSDTR FSOPEN FSCLOSE IOSTCTR2 IOSTDTR1 ISTCTR1 ISTCTR2 ISTDTR1 OSTCTR1 OSTDTR1 STCTR1 STINIT STDTR STSETST STCLEAR STBCTR1 STBDTR STBDNEXT STBDSGTN FSBCTR1 FSBDTR FSBOPEN FSBCLOSE FSBUFLOW FSBOFLOW FSBSKOFF FSBSYNC FSBSBUF ISTGLINE ISTDIPFX ISRCTR2 ISRDTR SRCTR1 SRDTR SRBCTR6 SRBDTR SRBINIT SRBUFLOW SRBOFLOW SRBSKOFF SRBSYNC SRBSBUF SRBDALC OSRCTR1 OSRDTR"
sok=0
for f in $STF; do $BCC -c -m32 -D__WIN32__ $SINC "$STSRC/$f.CPP" -o "$RB/streams/$f.o" >/dev/null 2>&1 && sok=$((sok+1)); done
echo "streams ok=$sok"
$MDAR -o $RB/mdowl.lib $RB/owl/*.o >/dev/null 2>&1
$MDAR -o $RB/mdstreams.lib $RB/streams/*.o >/dev/null 2>&1
echo "=== link ==="
$MDLINK -m32 --subsystem gui $RB/railc/*.o $RB/mdowl.lib $RB/mdstreams.lib C:/language/mdbcc/wrk_oracle/mdcw32.lib C:/language/mdbcc/wrk_oracle/mdbids.lib -o $RB/railc.exe > $RB/link.log 2>&1
echo "link exit=$?"
echo "--- unresolved ---"
grep -A60 "unresolved external" $RB/link.log
