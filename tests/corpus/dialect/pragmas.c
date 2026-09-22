/* Borland #pragma forms. mdbcc ignores #pragma; bcc32 accepts. */
#include <stdio.h>
#pragma warn -8057
#pragma argsused
int f(int unused){ return 42; }
int main(void){
    printf("%d\n", f(0)); /* 42 */
    return 0;
}
