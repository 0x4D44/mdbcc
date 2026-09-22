/* printf field width + left-justify (part 2). Strict C89. */
#include <stdio.h>
int main(void){
    printf("[%-6x]\n", 0xABu);
    printf("[%8s]\n", "hi");
    printf("[%-8s]\n", "hi");
    printf("[%3c]\n", 'Q');
    printf("[%-3c]\n", 'Q');
    return 0;
}
