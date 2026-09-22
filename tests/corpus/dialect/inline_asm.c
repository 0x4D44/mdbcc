// oracle: skip bcc32 5.5.1 free tools have no tasm32.exe (inline asm shells out to TASM); mdbcc parse-smoke only
/* Borland inline asm. mdbcc parses & drops it (slice 14). Kept as an mdbcc
   parse-smoke tripwire: bcc32 5.5.1's free package cannot assemble inline
   asm (needs the separately-sold TASM), so it is NOT acceptance-testable
   with the acquired reference. NOT run behaviourally in v1. */
#include <stdio.h>
int answer(void){
    int r;
    r = 0;
    asm { mov eax, 42 }
    asm { mov r, eax }
    return r;
}
int main(void){
    printf("%d\n", answer());
    return 0;
}
