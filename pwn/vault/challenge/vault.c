/* Vault - runs whatever code you give it, but the door only opens so far.
 * mmaps an RWX page, reads your shellcode into it, installs a seccomp filter, then jumps to it.
 * execve/execveat are NOT on the allowlist, so a shell won't help - you must open/read/write /flag.
 * build: gcc vault.c -o vault -lseccomp -no-pie
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <seccomp.h>

static void lockdown(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    int allow[] = {
        SCMP_SYS(openat), SCMP_SYS(open), SCMP_SYS(read), SCMP_SYS(write),
        SCMP_SYS(close), SCMP_SYS(lseek), SCMP_SYS(fstat), SCMP_SYS(newfstatat),
        SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(brk), SCMP_SYS(rt_sigreturn),
        SCMP_SYS(exit), SCMP_SYS(exit_group),
    };
    for (unsigned i = 0; i < sizeof allow / sizeof allow[0]; i++)
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0);
    seccomp_load(ctx);                 /* sets no_new_privs + loads the filter */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANON | MAP_PRIVATE, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return 1; }
    puts("=== Vault ===");
    puts("send your shellcode (up to 4096 bytes), then EOF:");
    ssize_t n = read(0, page, 0x1000);
    if (n <= 0) return 1;
    lockdown();                        /* seccomp: open/read/write only - no execve */
    ((void (*)(void))page)();
    return 0;
}
