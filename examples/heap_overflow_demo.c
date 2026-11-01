/*
 * RuntimeX / HeapSentry Vulnerability Demo: Heap Buffer Overflow
 *
 * Vulnerability Class: CWE-122 (Heap-based Buffer Overflow)
 * Severity: CRITICAL
 *
 * Description:
 *   Allocates a fixed-size heap buffer (16 bytes) and writes unbounded
 *   data past the end of the buffer using strcpy() or direct indexing.
 *   This corrupts adjacent heap metadata and destroys HeapSentry's
 *   16-byte right red-zone canary (0xFEEDFACEDEADBEEF).
 *
 * Safe Alternative:
 *   Use size-bounded copying functions (strncpy, strlcpy, snprintf) and
 *   explicitly check input length before copying into heap buffers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_heap_copy(const char *input) {
    char *buf = (char *)malloc(16);
    if (!buf) {
        perror("malloc failed");
        exit(1);
    }

    printf("[+] Allocated 16 bytes at %p\n", (void *)buf);
    printf("[!] Copying %zu bytes into 16-byte buffer...\n", strlen(input));

    /* VULNERABILITY: Writing beyond 16 bytes overwrites the right canary */
    strcpy(buf, input);

    printf("[+] Buffer contents: %s\n", buf);
    printf("[*] Freeing buffer (canary verification will trigger here)...\n");

    /* HeapSentry verifies the canary during free() */
    free(buf);
}

int main(int argc, char **argv) {
    const char *payload = "AAAABBBBCCCCDDDD_OVERFLOW_RIGHT_CANARY!";

    if (argc > 1) {
        payload = argv[1];
    } else {
        /* Check if stdin has data */
        static char stdin_buf[256];
        if (fgets(stdin_buf, sizeof(stdin_buf), stdin)) {
            size_t len = strlen(stdin_buf);
            if (len > 0 && stdin_buf[len - 1] == '\n') {
                stdin_buf[len - 1] = '\0';
            }
            if (strlen(stdin_buf) > 0) {
                payload = stdin_buf;
            }
        }
    }

    printf("=== Heap Buffer Overflow Demo ===\n");
    vulnerable_heap_copy(payload);
    printf("[+] Program completed normally.\n");
    return 0;
}
