/* Dispatch - Sparrow Freight dispatch terminal.
 * Reads a waybill into an undersized buffer. NX + no canary + no PIE, dynamically linked.
 * build: gcc dispatch.c -o dispatch -fno-stack-protector -no-pie -O0
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* handy little gadget the linker left in (modern glibc dropped __libc_csu_init) */
asm(".global pop_rdi_ret\n"
    "pop_rdi_ret:\n"
    "    pop %rdi\n"
    "    ret\n");

void vuln(void) {
    char buf[64];
    puts("dispatch> enter waybill number:");
    read(0, buf, 512);            /* overflow: 64-byte buffer */
    puts("waybill logged.");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== Sparrow Freight dispatch terminal ===");
    vuln();
    return 0;
}
