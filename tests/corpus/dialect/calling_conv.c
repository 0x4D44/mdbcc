/* Borland/Win32 calling-convention keywords. O3 acceptance + mdbcc smoke. */
#include <stdio.h>
int __cdecl    addc(int a, int b){ return a + b; }
int __stdcall  adds(int a, int b){ return a + b; }
int __fastcall addf(int a, int b){ return a + b; }
int main(void){
    printf("%d\n", addc(1,2) + adds(3,4) + addf(5,6)); /* 21 */
    return 0;
}
