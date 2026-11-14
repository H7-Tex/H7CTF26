#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include "manifold.h"

#define CACHE_SLOTS 16
#define PIE_SLOT 3
#define LIBC_SLOT 10
#define PING_BUDGET 40
#define WKEY 0x9e3779b97f4a7c15ULL
#define WATCHDOG 290

static const char glyphs[26] = "MNBVCXZLKJHGFDSAPOIUYTREW";

typedef long (*maint_fn)(const char *);

maint_fn maintenance_fn = 0;

struct chart_cache {
    uint64_t datum[CACHE_SLOTS];
};

struct beacon {
    uint64_t addr;
    uint64_t gate_lo;
    uint64_t gate_hi;
    int armed;
};

struct station {
    int rov;
    int reg;
    int engaged;
    int equalized;
    int equalized_at;
    int caught;
    int ping_left;
    struct beacon bcn;
    struct chart_cache *cache;
};

struct verb {
    const char *name;
    int (*fn)(struct station *, char *);
};

static char wany[MANIFOLD_NODES][MANIFOLD_NODES];

static int move_set(int u, int *out)
{
    int k = 0;
    for (int i = 0; i < manifold_deg[u]; i++)
        out[k++] = manifold_adj[u][i];
    out[k++] = u;
    return k;
}

static int is_sink(int u)
{
    for (int i = 0; i < MANIFOLD_NSINKS; i++)
        if (manifold_sinks[i] == u)
            return 1;
    return 0;
}

static int contains(int *arr, int n, int v)
{
    for (int i = 0; i < n; i++)
        if (arr[i] == v)
            return 1;
    return 0;
}

static void solve_tablebase(void)
{
    int rm[MANIFOLD_MAXDEG + 1], cm[MANIFOLD_MAXDEG + 1];
    memset(wany, 0, sizeof(wany));
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int r = 0; r < MANIFOLD_NODES; r++) {
            int nr = move_set(r, rm);
            for (int c = 0; c < MANIFOLD_NODES; c++) {
                if (r == c || wany[r][c])
                    continue;
                int nc = move_set(c, cm);
                int won = 0;
                for (int i = 0; i < nr; i++) {
                    int rp = rm[i];
                    if (rp == c || contains(cm, nc, rp))
                        continue;
                    if (is_sink(rp)) {
                        won = 1;
                        break;
                    }
                    int allok = 1;
                    for (int j = 0; j < nc; j++) {
                        if (!wany[rp][cm[j]]) {
                            allok = 0;
                            break;
                        }
                    }
                    if (allok) {
                        won = 1;
                        break;
                    }
                }
                if (won) {
                    wany[r][c] = 1;
                    changed = 1;
                }
            }
        }
    }
}

static int reg_reply(int rp, int c)
{
    int cm[MANIFOLD_MAXDEG + 1];
    int nc = move_set(c, cm);
    for (int i = 0; i < nc; i++)
        if (cm[i] == rp)
            return rp;
    for (int i = 0; i < nc; i++)
        if (!wany[rp][cm[i]])
            return cm[i];
    return cm[0];
}

static int probe_qword(uint64_t addr, uint64_t *out)
{
    int fd[2];
    if (pipe(fd) != 0)
        return -1;
    ssize_t w = write(fd[1], (void *)(uintptr_t)addr, 8);
    int ok = (w == 8);
    if (ok && out)
        if (read(fd[0], out, 8) != 8)
            ok = 0;
    close(fd[0]);
    close(fd[1]);
    return ok ? 0 : -1;
}

static uint64_t decode_marks(const char *s)
{
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        int idx = -1;
        for (int i = 0; i < 25; i++)
            if (glyphs[i] == *p) {
                idx = i;
                break;
            }
        if (idx < 0)
            return 0;
        v = v * 25ULL + (uint64_t)idx;
    }
    return v ^ WKEY;
}

static void render_banner(void)
{
    puts("Cistern-9 salvage uplink. Text console only.");
    puts("The manifold is sealed behind the trim regulator.");
    puts("Type help for the verb list.");
}

static void arm_gate(struct station *st, int si)
{
    uintptr_t anchor = 0;
    switch (si) {
    case 0:
        anchor = (uintptr_t)&render_banner;
        break;
    case 1:
        anchor = (uintptr_t)dlsym(RTLD_DEFAULT, "puts");
        break;
    case 2:
        anchor = (uintptr_t)&maintenance_fn;
        break;
    default:
        anchor = (uintptr_t)&glyphs[0];
        break;
    }
    st->bcn.gate_lo = (uint64_t)(anchor & ~0xFFFULL);
    st->bcn.gate_hi = st->bcn.gate_lo + 0x1000ULL;
    st->bcn.armed = 1;
}

static int cmd_help(struct station *st, char *arg)
{
    (void)st;
    (void)arg;
    puts("verbs: help, survey <node>, dive, valve <node>, look");
    puts("       mark <marks>, ping, set <hexqword>, maintenance <args>, override <hexqword>");
    return 0;
}

static int cmd_look(struct station *st, char *arg)
{
    (void)arg;
    if (!st->engaged) {
        puts("The drone idles at the intake. The regulator has not been engaged.");
        return 0;
    }
    if (st->caught) {
        puts("The regulator has you pinned. Re-engage to try the trim standoff again.");
        return 0;
    }
    if (!st->equalized) {
        printf("drone at compartment %d, regulator at compartment %d\n", st->rov, st->reg);
        return 0;
    }
    printf("shaft open. equalization sink %d. transponder live. ping budget %d.\n",
           st->equalized_at, st->ping_left);
    printf("beacon target 0x%016llx\n", (unsigned long long)st->bcn.addr);
    return 0;
}

static int cmd_survey(struct station *st, char *arg)
{
    (void)st;
    if (!arg) {
        puts("survey which compartment?");
        return 0;
    }
    int n = atoi(arg);
    if (n < 0 || n >= MANIFOLD_NODES) {
        puts("no such compartment.");
        return 0;
    }
    printf("compartment %d bulkheads to:", n);
    for (int i = 0; i < manifold_deg[n]; i++)
        printf(" %d", manifold_adj[n][i]);
    printf("\n");
    if (is_sink(n))
        puts("this compartment is an equalization chamber.");
    return 0;
}

static int cmd_dive(struct station *st, char *arg)
{
    (void)arg;
    if (st->equalized) {
        puts("the shaft is already open.");
        return 0;
    }
    st->engaged = 1;
    st->caught = 0;
    st->rov = ROV_START;
    st->reg = REG_START;
    printf("engaged. drone at %d, regulator at %d.\n", st->rov, st->reg);
    return 0;
}

static int cmd_valve(struct station *st, char *arg)
{
    if (!st->engaged || st->equalized) {
        puts("the regulator is not listening.");
        return 0;
    }
    if (st->caught) {
        puts("you are pinned. dive again.");
        return 0;
    }
    if (!arg) {
        puts("toggle toward which compartment?");
        return 0;
    }
    int rp = atoi(arg);
    int rm[MANIFOLD_MAXDEG + 1];
    int nr = move_set(st->rov, rm);
    if (!contains(rm, nr, rp)) {
        puts("no bulkhead there.");
        return 0;
    }
    st->rov = rp;
    int cp = reg_reply(rp, st->reg);
    st->reg = cp;
    if (cp == rp) {
        st->caught = 1;
        st->engaged = 0;
        puts("the regulator equalizes onto you. the drone is crushed.");
        return 0;
    }
    printf("drone at %d, regulator at %d.\n", st->rov, st->reg);
    if (is_sink(rp)) {
        st->equalized = 1;
        st->equalized_at = rp;
        int si = 0;
        for (int i = 0; i < MANIFOLD_NSINKS; i++)
            if (manifold_sinks[i] == rp)
                si = i;
        arm_gate(st, si);
        st->cache = calloc(1, sizeof(struct chart_cache));
        for (int i = 0; i < CACHE_SLOTS; i++)
            st->cache->datum[i] = 0x5000000000ULL + (uint64_t)i * 0x111ULL;
        st->cache->datum[PIE_SLOT] = (uint64_t)(uintptr_t)&render_banner;
        st->cache->datum[LIBC_SLOT] = (uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "puts");
        puts("the bulkheads equalize. the central shaft grinds open.");
        printf("survey datum staged at %p\n", (void *)st->cache);
        puts("the transponder wakes. play knot-marks on the sounding line.");
    }
    return 0;
}

static int cmd_mark(struct station *st, char *arg)
{
    if (!st->equalized) {
        puts("the transponder is dark.");
        return 0;
    }
    if (!arg) {
        puts("no marks read.");
        return 0;
    }
    st->bcn.addr = decode_marks(arg);
    printf("sounding line reads 0x%016llx\n", (unsigned long long)st->bcn.addr);
    return 0;
}

static int cmd_ping(struct station *st, char *arg)
{
    (void)arg;
    if (!st->equalized) {
        puts("the transponder is dark.");
        return 0;
    }
    if (st->ping_left <= 0) {
        puts("the transponder is out of charge.");
        return 0;
    }
    st->ping_left--;
    uint64_t base = (uint64_t)(uintptr_t)st->cache;
    uint64_t end = base + sizeof(struct chart_cache);
    if (st->bcn.addr >= base && st->bcn.addr + 8 <= end) {
        uint64_t v = 0;
        if (probe_qword(st->bcn.addr, &v) == 0)
            printf("chart cache holds 0x%016llx\n", (unsigned long long)v);
        else
            puts("no return.");
        return 0;
    }
    if (probe_qword(st->bcn.addr, 0) == 0)
        puts("echo: solid bottom.");
    else
        puts("echo: open water.");
    return 0;
}

static int cmd_set(struct station *st, char *arg)
{
    if (!st->equalized) {
        puts("the transponder is dark.");
        return 0;
    }
    if (!arg) {
        puts("set to what depth?");
        return 0;
    }
    uint64_t val = strtoull(arg, 0, 16);
    if (!st->bcn.armed || st->bcn.addr < st->bcn.gate_lo || st->bcn.addr + 8 > st->bcn.gate_hi) {
        puts("the sounding line is slack. that depth is out of trim band.");
        return 0;
    }
    *(volatile uint64_t *)(uintptr_t)st->bcn.addr = val;
    puts("the transponder writes the new bottom.");
    return 0;
}

static int cmd_maintenance(struct station *st, char *arg)
{
    (void)st;
    if (!maintenance_fn) {
        puts("no maintenance handler is bound.");
        return 0;
    }
    maintenance_fn(arg ? arg : "");
    return 0;
}

static int cmd_override(struct station *st, char *arg)
{
    if (!st->equalized) {
        puts("the manual override panel is behind the shaft.");
        return 0;
    }
    if (!arg) {
        puts("override with what value?");
        return 0;
    }
    uint64_t val = strtoull(arg, 0, 16);
    if (st->cache)
        st->cache->datum[0] = val;
    puts("the manual override panel clunks. nothing obvious happens.");
    return 0;
}

static const struct verb verbs[] = {
    {"help", cmd_help},
    {"survey", cmd_survey},
    {"dive", cmd_dive},
    {"valve", cmd_valve},
    {"look", cmd_look},
    {"mark", cmd_mark},
    {"ping", cmd_ping},
    {"set", cmd_set},
    {"maintenance", cmd_maintenance},
    {"override", cmd_override},
    {0, 0}
};

static void alarm_handler(int sig)
{
    (void)sig;
    const char *m = "uplink timeout.\n";
    write(1, m, strlen(m));
    _exit(0);
}

int main(void)
{
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(WATCHDOG);

    solve_tablebase();

    struct station st;
    memset(&st, 0, sizeof(st));
    st.ping_left = PING_BUDGET;

    render_banner();

    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = 0;
        if (n == 0)
            continue;
        char *sp = strchr(line, ' ');
        char *arg = 0;
        if (sp) {
            *sp = 0;
            arg = sp + 1;
            while (*arg == ' ')
                arg++;
            if (*arg == 0)
                arg = 0;
        }
        int handled = 0;
        for (int i = 0; verbs[i].name; i++) {
            if (strcmp(verbs[i].name, line) == 0) {
                verbs[i].fn(&st, arg);
                handled = 1;
                break;
            }
        }
        if (!handled)
            puts("the console rejects that verb.");
    }
    return 0;
}
