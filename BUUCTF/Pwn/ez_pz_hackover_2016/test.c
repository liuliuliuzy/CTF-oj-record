#include <string.h>
#include <stdio.h>
int main()
{
    char s[20] = "abc";
    strcat(s, "aaaaaaaaaaaaaaaabcdeaaaaaaaaaaaaaabb");
    puts(s);
    return 0;
}