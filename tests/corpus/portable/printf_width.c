/* printf field width + left-justify (part 1). Strict C89.
   Split into two files to stay under the PE writer's current 4 KB
   per-section limit (see wrk_journals 2026.05.17 JRN). */
#include <stdio.h>
int main(void){
    printf("[%5d]\n", 42);
    printf("[%-5d]\n", 42);
    printf("[%5d]\n", -42);
    printf("[%5u]\n", 7u);
    printf("[%6x]\n", 0xABu);
    return 0;
}
