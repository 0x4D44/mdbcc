// oracle: skip near/far are 16-bit-only; bcc32 5.5.1 (Win32) rejects them; out of Win64 rebuild scope; mdbcc parse-smoke only
/* Borland 16-bit memory-model keywords (near/far). bcc32-32 REJECTS these
   ("Declaration syntax error") — they are 16-bit DOS-era, explicitly the
   project's counter-goal (Win64 rebuild). Kept only as an mdbcc-tolerance
   parse-smoke: mdbcc parses & ignores them so legacy source still builds. */
#include <stdio.h>
int far add_far(int a, int b){ return a + b; }
int main(void){
    int v;
    int far *p;
    v = 5;
    p = &v;
    printf("%d\n", add_far(*p, 7)); /* 12 */
    return 0;
}
