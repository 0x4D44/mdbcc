/* printf '0' (zero) flag (part 2). Strict C89. */
#include <stdio.h>
int main(void){
    printf("[%06u]\n", 1234u);
    printf("[%-08d]\n", 42);   /* '-' overrides '0' -> left, spaces */
    printf("[%02d]\n", 12345); /* width < digits: no truncation */
    return 0;
}
