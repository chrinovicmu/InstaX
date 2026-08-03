#include <stdio.h>
#include <stdlib.h>


int add(int x,int y)
{
    return x + y;
}
int main(int argc, char *argv[])
{
    printf("%d\n", add(1,2)); 
    return EXIT_SUCCESS;
}

