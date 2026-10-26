/*
 * Deliberately vulnerable local test target for Crashlab.
 *
 * This is defensive research tooling: the program is intentionally buggy so
 * that ASan/GDB evidence can be collected locally. Do not deploy it.
 *
 * Build (Linux/macOS):
 *   make            # plain build: ./target
 *   make asan       # instrumented: ./target_asan
 *
 * Input handling: the first byte selects the bug. The payload may come from
 * stdin or from an optional file path in argv[1].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__GNUC__) || defined(__clang__)
#define CRASHLAB_NOINLINE __attribute__((noinline))
#else
#define CRASHLAB_NOINLINE
#endif

static void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fputs("xmalloc failed\n", stderr);
        exit(2);
    }
    return ptr;
}

CRASHLAB_NOINLINE static void heap_overflow(void) {
    char *buf = (char *)xmalloc(16);
    memset(buf, 'A', 16);
    /* One byte past the end. ASan reports heap-buffer-overflow (WRITE of size 1). */
    buf[16] = 'X';
    free(buf);
    puts("heap path completed without an abort");
}

CRASHLAB_NOINLINE static void use_after_free(void) {
    char *buf = (char *)xmalloc(32);
    memset(buf, 'B', 32);
    free(buf);
    /* Use-after-free read. A plain build may not fault; ASan does. */
    volatile char value = buf[0];
    printf("uaf byte: %d\n", (int)value);
}

CRASHLAB_NOINLINE static void double_free(void) {
    char *buf = (char *)xmalloc(24);
    free(buf);
    free(buf); /* glibc aborts: "free(): double free detected" */
}

CRASHLAB_NOINLINE static void stack_overflow(void) {
    volatile unsigned char buffer[8];
    memset((void *)buffer, 'S', 64); /* overflow intended */
    printf("stack byte: %u\n", (unsigned)buffer[0]);
}

CRASHLAB_NOINLINE static void null_deref(void) {
    volatile int *pointer = (volatile int *)0;
    *pointer = 1; /* SIGSEGV on POSIX, access violation on Windows */
}

CRASHLAB_NOINLINE static void wait_forever(void) {
    puts("sleeping");
    fflush(stdout);
    sleep(3600);
}

int main(int argc, char **argv) {
    FILE *input = stdin;
    if (argc > 1) {
        input = fopen(argv[1], "rb");
        if (input == NULL) {
            perror("fopen");
            return 2;
        }
    }

    unsigned char mode = 'N';
    if (fread(&mode, 1, 1, input) != 1) {
        mode = 'N';
    }
    if (argc > 1) {
        fclose(input);
    }

    switch (mode) {
        case 'H':
            heap_overflow();
            break;
        case 'U':
            use_after_free();
            break;
        case 'D':
            double_free();
            break;
        case 'S':
            stack_overflow();
            break;
        case 'P':
            null_deref();
            break;
        case 'T':
            wait_forever();
            break;
        case 'N':
        default:
            puts("normal termination");
            break;
    }
    return 0;
}
