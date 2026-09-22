/* printf '0' (zero) flag, incl. negative sign placement (part 1). C89. */
#include <stdio.h>
int main(void){
    printf("[%08d]\n", 42);
    printf("[%08d]\n", -42);
    printf("[%08x]\n", 0xBEEFu);
    printf("[%04X]\n", 0x2Au);
    return 0;
}
