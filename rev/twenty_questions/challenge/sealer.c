#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#define NROUNDS 256
#define NCORE   16

struct win {
    uint8_t  ct[256];
    uint8_t  sched[256];
    uint8_t  pos[256];
    uint8_t  real_mask[256];
    uint32_t nrounds;
    uint8_t  _pad[4];
    uint8_t  digest[32];
    uint8_t  _tail[0x1000 - 0x428];
};
volatile struct win g_win;

char honey[] = "H7CTF{n0t_the_real_0ne_stepper}";

static uint8_t prf(const uint8_t *k, uint8_t p) {
    uint64_t a, b;
    memcpy(&a, k, 8);
    memcpy(&b, k + 8, 8);
    uint64_t x = a ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(p + 1));
    for (int i = 0; i < 6; i++) {
        x += b;  x ^= (x << 13) | (x >> 51);
        b ^= x;  b  = (b << 7)  | (b >> 57);
    }
    return (uint8_t)(x ^ (x >> 32) ^ (x >> 16));
}

static void fold(volatile uint8_t *d, uint8_t b, uint8_t p) {
    uint8_t h = d[(p * 7 + b) & 31];
    d[(p * 7 + b) & 31] = (uint8_t)(h + b * 31 + p);
    d[(b) & 31] ^= (uint8_t)(h ^ (b << 1) ^ p);
}

__attribute__((noinline)) void confess(uint8_t b, uint8_t p) {
    __asm__ volatile("" : : "r"(b), "r"(p) : "memory");
}

__attribute__((noinline)) void pre_loop(void) {
    __asm__ volatile("" : : : "memory");
}

static void get_seed(uint8_t *k, size_t n) {
    const char *s = getenv("TQ_SEED");
    if (s && *s) { for (size_t i = 0; i < n; i++) k[i] = (uint8_t)(s[i % strlen(s)] + i * 31); return; }
    ssize_t r = 0; size_t off = 0;
    while (off < n && (r = getrandom(k + off, n - off, 0)) > 0) off += (size_t)r;
}

static uint64_t rng_s;
static uint64_t rng(void) { rng_s ^= rng_s << 13; rng_s ^= rng_s >> 7; rng_s ^= rng_s << 17; return rng_s; }

int main(void) {
    uint8_t core[NCORE] = {0};
    const char *f = getenv("FLAG");
    if (f) {
        const char *o = strchr(f, '{');
        const char *core_src = o ? o + 1 : f;
        for (int i = 0; i < NCORE && core_src[i] && core_src[i] != '}'; i++) core[i] = (uint8_t)core_src[i];
    }
    uint8_t seed_key[16];
    get_seed(seed_key, sizeof seed_key);
    memcpy(&rng_s, seed_key, 8);
    if (!rng_s) rng_s = 0x1234567deadbeefULL;

    uint8_t slot_of[NCORE];
    uint8_t used[256] = {0};
    for (int p = 0; p < NCORE; p++) {
        uint8_t s;
        do { s = (uint8_t)(rng() & 0xFF); } while (used[s]);
        used[s] = 1; slot_of[p] = s;
    }
    for (int s = 0; s < 256; s++) g_win.ct[s] = (uint8_t)(rng() & 0xFF);
    for (int p = 0; p < NCORE; p++) g_win.ct[slot_of[p]] = (uint8_t)(core[p] ^ prf(seed_key, (uint8_t)p));

    uint8_t perm[256];
    for (int i = 0; i < 256; i++) perm[i] = (uint8_t)i;
    for (int i = 255; i > 0; i--) { int j = (int)(rng() % (uint64_t)(i + 1)); uint8_t t = perm[i]; perm[i] = perm[j]; perm[j] = t; }
    uint8_t pos_of_slot[256];
    memset(pos_of_slot, 0xFF, sizeof pos_of_slot);
    for (int p = 0; p < NCORE; p++) pos_of_slot[slot_of[p]] = (uint8_t)p;
    for (int r = 0; r < 256; r++) {
        g_win.sched[r] = perm[r];
        g_win.pos[r] = pos_of_slot[perm[r]];
        g_win.real_mask[r] = (g_win.pos[r] < NCORE) ? 1 : 0;
    }
    memset((void *)g_win.digest, 0, sizeof g_win.digest);
    g_win.nrounds = NROUNDS;

    memset(core, 0, sizeof core);

    volatile struct win *w = &g_win;
    pre_loop();
    for (uint32_t r = 0; r < w->nrounds; r++) {
        uint8_t s = w->sched[r];
        uint8_t p = w->pos[r];
        uint8_t b = (uint8_t)(w->ct[s] ^ prf(seed_key, p));
        confess(b, p);
        fold(w->digest, b, p);
        w->ct[s] = 0;
    }
    volatile char sink = honey[0]; (void)sink;
    return 0;
}
