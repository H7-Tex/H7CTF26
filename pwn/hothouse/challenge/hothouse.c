#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#define ROWS 32
#define COLS 32
#define ROW_BYTES 4
#define FABRIC_BYTES 128
#define CELLS 1024
#define GENERATIONS 7
#define META_SIZE 4096
#define ARENA_SIZE (META_SIZE * 2)

#define SEED_BUDGET 4096
#define INCUBATE_BUDGET 64
#define PROBE_BUDGET 20000

static const int stencil[6][2] = {
    {-1, 0}, {1, 0}, {0, 1}, {0, -1}, {-1, 1}, {1, -1}
};

static unsigned char *arena;
static unsigned char *fabric;
static unsigned char lattice_seed[CELLS];
static unsigned char substrate[CELLS];

static long seed_ops;
static long incubate_ops;
static long probe_ops;
static int has_fired;

static int cell(int r, int c) { return r * COLS + c; }

static void fill_random_bits(unsigned char *dst, int n) {
    unsigned char raw[CELLS];
    getrandom(raw, n, 0);
    for (int i = 0; i < n; i++) dst[i] = raw[i] & 1u;
}

static void place_flag_path(void) {
    const char *p = getenv("FLAGPATH");
    if (!p) p = "/flag_0000000000000000";
    size_t len = strlen(p);
    if (len + 1 > META_SIZE - 128) len = META_SIZE - 129;
    unsigned int slot;
    getrandom(&slot, sizeof(slot), 0);
    size_t off = 64 + (slot % (META_SIZE - 192));
    memcpy(arena + off, p, len);
    arena[off + len] = 0;
}

static void setup(void) {
    arena = mmap(NULL, ARENA_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) { perror("map"); exit(1); }
    fabric = arena + META_SIZE;
    if (mprotect(fabric, META_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("prot");
        exit(1);
    }
    fill_random_bits(substrate, CELLS);
    memset(lattice_seed, 0, CELLS);
    place_flag_path();
}

static void incubate(void) {
    unsigned char cur[CELLS];
    unsigned char nxt[CELLS];
    memcpy(cur, lattice_seed, CELLS);
    for (int g = 0; g < GENERATIONS; g++) {
        for (int r = 0; r < ROWS; r++) {
            for (int c = 0; c < COLS; c++) {
                unsigned char v = 0;
                for (int k = 0; k < 6; k++) {
                    int rr = r + stencil[k][0];
                    int cc = c + stencil[k][1];
                    if (rr >= 0 && rr < ROWS && cc >= 0 && cc < COLS)
                        v ^= cur[cell(rr, cc)];
                }
                nxt[cell(r, c)] = v ^ substrate[cell(r, c)];
            }
        }
        memcpy(cur, nxt, CELLS);
    }
    memset(fabric, 0, FABRIC_BYTES);
    for (int r = 0; r < ROWS; r++)
        for (int c = 0; c < COLS; c++)
            if (cur[cell(r, c)])
                fabric[r * ROW_BYTES + (c >> 3)] |= (1u << (c & 7));
}

static void render(void) {
    for (int r = 0; r < ROWS; r++) {
        char line[COLS + 2];
        for (int c = 0; c < COLS; c++) {
            unsigned char bit = fabric[r * ROW_BYTES + (c >> 3)] & (1u << (c & 7));
            line[c] = bit ? '#' : '.';
        }
        line[COLS] = '\n';
        line[COLS + 1] = 0;
        fputs(line, stdout);
    }
}

static void install_policy(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 257, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 60, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 231, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(code) / sizeof(code[0])),
        .filter = code,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("nnp"); exit(1); }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        perror("seccomp");
        exit(1);
    }
}

static void fire(void) {
    fflush(stdout);
    close(0);
    install_policy();
    void (*entry)(void) = (void (*)(void))fabric;
    entry();
    _exit(0);
}

static void handle_seed(int r, int c) {
    if (seed_ops >= SEED_BUDGET) { puts("E: seed budget exhausted"); return; }
    if (r < 0 || r >= ROWS || c < 0 || c >= COLS) { puts("E: cell out of range"); return; }
    seed_ops++;
    lattice_seed[cell(r, c)] = 1;
    puts("ok");
}

static void handle_probe(int r, int c) {
    if (probe_ops >= PROBE_BUDGET) { puts("E: probe budget exhausted"); return; }
    if (c > 31 || r > 31) { puts("E: cell out of range"); return; }
    long off = (long)r * ROW_BYTES + (c >> 3);
    if (off < -META_SIZE || off >= FABRIC_BYTES) { puts("E: sensor offline"); return; }
    probe_ops++;
    unsigned char v = fabric[off];
    printf("Tc: %u\n", (unsigned)v);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setup();
    puts("hothouse coprocessor control link");
    puts("commands: SEED r c | INCUBATE | PROBE r c | RENDER | FIRE");
    char linebuf[128];
    while (fgets(linebuf, sizeof(linebuf), stdin)) {
        int a, b;
        if (sscanf(linebuf, "SEED %d %d", &a, &b) == 2) {
            handle_seed(a, b);
        } else if (strncmp(linebuf, "INCUBATE", 8) == 0) {
            if (incubate_ops >= INCUBATE_BUDGET) { puts("E: incubate budget exhausted"); continue; }
            incubate_ops++;
            incubate();
            puts("incubated");
        } else if (sscanf(linebuf, "PROBE %d %d", &a, &b) == 2) {
            handle_probe(a, b);
        } else if (strncmp(linebuf, "RENDER", 6) == 0) {
            render();
        } else if (strncmp(linebuf, "FIRE", 4) == 0) {
            if (has_fired) { puts("E: core already fired"); continue; }
            has_fired = 1;
            fire();
        } else {
            puts("E: unknown command");
        }
    }
    return 0;
}
