/*
 * RuntimeX target D: controlled vulnerable demo.
 *
 * WARNING — this file intentionally contains a heap buffer overflow
 * (writes past a too-small malloc with strcpy). It exists solely so a
 * human can observe in a controlled LOCAL environment what RuntimeX logs
 * around a memory-unsafe program. RuntimeX does not detect the overflow:
 * it records allocation lifecycle events; crash analysis is Person 2's
 * module. Run only on test data in this repository.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char *small;
    const char *payload = "overflow-payload-research-data-ONLY";

    if (argc > 1 && strcmp(argv[1], "--refuse") == 0) {
        puts("refusing to run by request");
        return 0;
    }

    small = malloc(8);
    if (small == NULL)
        return 1;

    strcpy(small, payload); /* INTENTIONAL heap overflow */

    free(small);
    puts("vulnerable_demo done");
    return 0;
}
