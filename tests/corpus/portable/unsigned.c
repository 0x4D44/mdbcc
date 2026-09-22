/* Unsigned arithmetic (well-defined wrap), %u / %x / shifts. Strict C89. */
#include <stdio.h>
int main(void){
    unsigned int u;
    int x;
    u = 4000000000u;
    printf("%u\n", u);                  /* 4000000000 */
    printf("%u\n", u + 1000000000u);    /* 705032704 (mod 2^32) */
    x = -1;
    printf("%u\n", (unsigned int)x);    /* 4294967295 */
    printf("%d\n", (1 << 20) - 1);      /* 1048575 */
    printf("%x\n", 0xABCDu);            /* abcd */
    return 0;
}
