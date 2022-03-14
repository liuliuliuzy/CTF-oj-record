#include <ctype.h>
#include <stdio.h>

int main(int argc, char const *argv[])
{
    int i;
    char A = 'A';
    printf("%02x\n", __ctype_b_loc(A) & 8);
    return 0;
}