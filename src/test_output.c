#include <stdio.h>

int main(void) {
    printf("This is a test of console output\n");
    fprintf(stderr, "This is a test of error output\n");
    fflush(stdout);
    fflush(stderr);
    return 0;
}
