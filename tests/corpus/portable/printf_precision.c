/* printf string precision (max chars) combined with width. Strict C89.
   (Integer precision is intentionally deferred in mdbcc v1 — not here.) */
#include <stdio.h>
int main(void){
    printf("[%.3s]\n", "hello");
    printf("[%8.3s]\n", "hello");
    printf("[%-8.3s]\n", "hello");
    printf("[%.10s]\n", "abc");
    printf("[%.0s]\n", "abc");
    return 0;
}
