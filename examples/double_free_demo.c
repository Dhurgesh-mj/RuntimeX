/*
 * RuntimeX / HeapSentry Vulnerability Demo: Double Free
 *
 * Vulnerability Class: CWE-415 (Double Free)
 * Severity: CRITICAL
 *
 * Description:
 *   Freeing the exact same heap memory pointer twice. In standard glibc,
 *   double-freeing corrupts the allocator free-lists (tcache or fastbins),
 *   allowing attackers to manipulate heap layout and achieve arbitrary write.
 *   HeapSentry tracks deallocations in a 512-slot quarantine ring buffer
 *   and intercepts duplicate free() calls before allocator corruption occurs.
 *
 * Safe Alternative:
 *   Neutralize pointers immediately after free():
 *     free(ptr);
 *     ptr = NULL;
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger_double_free(void) {
    char *token = (char *)malloc(32);
    if (!token) {
        perror("malloc failed");
        exit(1);
    }

    strncpy(token, "SECRET_SESSION_TOKEN_12345", 31);
    token[31] = '\0';
    printf("[+] Allocated 32 bytes at %p: '%s'\n", (void *)token, token);

    printf("[*] First free(token)...\n");
    free(token);
    printf("[+] Pointer deallocated and placed into quarantine ring buffer.\n");

    /* Simulating a flawed cleanup path or error handler */
    printf("[!] Triggering SECOND free(token) on same pointer...\n");
    /* VULNERABILITY: double free */
    free(token);

    printf("[+] Past second free.\n");
}

int main(void) {
    printf("=== Double Free Vulnerability Demo ===\n");
    trigger_double_free();
    printf("[+] Program completed.\n");
    return 0;
}
