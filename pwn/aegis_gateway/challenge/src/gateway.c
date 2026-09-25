#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_SECCOMP
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
/* v3.0+: block execve/execveat so a shell is out; the flag needs open/read/write */
static void install_seccomp(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
#endif

static void setup(void) {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
#ifdef WITH_SECCOMP
    install_seccomp();
#endif
}

static void banner(void) {
    puts("Aegis Gateway :: substation diagnostic console");
    puts("commands: STATUS | IDENT <name> | DIAG <len> | QUIT");
}

static void do_status(void) {
    printf("[status] uplink=OK feeder=SS-14 sessions=3\n");
}

/* operator identity is logged verbatim */
static void do_ident(char *name) {
#ifdef PATCH_FMT
    printf("%s", name);      /* v2.6+: the format-string bug was fixed in this release */
#else
    printf(name);            /* format string bug (info leak; %n write pre-FORTIFY) */
#endif
    putchar('\n');
}

/* capture probe data from the field unit */
static void do_diag(long len) {
    char buf[64];
    printf("[diag] send %ld bytes of probe data\n", len);
#ifdef WITH_FORTIFY
    /* volatile pointer hides static size from __builtin_object_size → no __read_chk */
    { char * volatile p = buf; int n = (int)read(0, p, (size_t)len);
      printf("[diag] captured %d bytes\n", n); }
#else
    int n = read(0, buf, len);   /* stack overflow when len > sizeof buf */
    printf("[diag] captured %d bytes\n", n);
#endif
}

int main(void) {
    setup();
    banner();
    char cmd[256];
    while (fgets(cmd, sizeof cmd, stdin)) {
        cmd[strcspn(cmd, "\r\n")] = 0;
        if (!strncmp(cmd, "STATUS", 6)) do_status();
        else if (!strncmp(cmd, "IDENT ", 6)) do_ident(cmd + 6);
        else if (!strncmp(cmd, "DIAG ", 5)) do_diag(atol(cmd + 5));
        else if (!strncmp(cmd, "QUIT", 4)) { puts("session closed"); break; }
        else puts("unknown command");
    }
    return 0;
}
