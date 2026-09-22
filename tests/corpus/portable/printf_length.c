/* printf length modifiers (l/h) parsed & ignored: long==int==4 bytes on
   mdbcc (LLP64), bcc32 (Win32) and MSVC. Strict C89. */
#include <stdio.h>
int main(void){
    long a;
    unsigned long b;
    short s;
    a = -123456;
    b = 4000000000UL;
    s = 1000;
    printf("[%ld]\n", a);
    printf("[%lu]\n", b);
    printf("[%lx]\n", b);
    printf("[%8ld]\n", a);
    printf("[%hd]\n", s);
    printf("[%05ld]\n", a);
    return 0;
}
