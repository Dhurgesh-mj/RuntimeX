/*
 * RuntimeX / HeapSentry Vulnerability Demo: Integer Overflow Leading to Heap Overflow
 *
 * Vulnerability Class: CWE-190 (Integer Overflow) / CWE-122 (Heap Buffer Overflow)
 * Severity: CRITICAL
 *
 * Description:
 *   An arithmetic calculation used to determine allocation size overflows,
 *   causing a much smaller buffer to be allocated than intended.
 *   Subsequent loops write the full expected amount of data, causing a
 *   massive heap buffer overflow that obliterates adjacent canaries.
 *
 * Safe Alternative:
 *   Use overflow-checked arithmetic (e.g., __builtin_mul_overflow or calloc)
 *   to ensure multiplication cannot wrap around before allocation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_items(unsigned int count) {
    /*
     * VULNERABILITY: If count is large, count * sizeof(int) wraps around.
     * For example, count = 1073741825 (0x40000001)
     * count * 4 = 0x100000004 = 4 bytes (in 32-bit integer arithmetic)
     */
    unsigned int bytes = count * sizeof(int);
    printf("[!] Requested count: %u, calculated allocation bytes: %u\n", count, bytes);

    int *items = (int *)malloc(bytes);
    if (!items) {
        perror("malloc failed");
        return;
    }

    printf("[+] Allocated buffer at %p (%u bytes)\n", (void *)items, bytes);
    printf("[!] Writing 8 elements into allocated buffer...\n");

    /* Writing beyond the undersized buffer */
    for (unsigned int i = 0; i < 8; i++) {
        items[i] = 0x41414141 + (int)i;
    }

    printf("[*] Freeing buffer to verify canaries...\n");
    free(items);
}

int main(int argc, char **argv) {
    /* Simulated small overflow: request 1 element (4 bytes), but write 8 elements (32 bytes) */
    unsigned int count = 1;
    if (argc > 1) {
        count = (unsigned int)atoi(argv[1]);
    }

    printf("=== Integer Overflow -> Heap Overflow Demo ===\n");
    process_items(count);
    printf("[+] Program completed.\n");
    return 0;
}
