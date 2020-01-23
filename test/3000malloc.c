#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 10

int main()
{
    char *buf[BUFF_SIZE];

    for (int i = 0; i < BUFF_SIZE; i++)
    {
            buf[i] = (char *)malloc(4096);
            printf("buf[%d]:    %016llx\n", i, (unsigned long long) buf[i]);
    }

    /* We need to sleep long enough to read /proc/pid/pagemap */
    sleep(3);

    for (int i = 0; i < BUFF_SIZE; i++) {
            free(buf[i]);
    }

    return 0;
}
