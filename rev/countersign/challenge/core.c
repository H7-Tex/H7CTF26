#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define NREG 8
#define NWORD 6
#define INLEN 24
#define NROUNDS 12
#define MAXBLOCKS 256
#define MAXCODE 512
#define MAXEDGES 16
#define STEP_CAP 200000

#define OP_END 0x00
#define OP_LDI 0x01
#define OP_MOV 0x02
#define OP_ADD 0x03
#define OP_XOR 0x04
#define OP_AND 0x05
#define OP_OR 0x06
#define OP_ROL 0x07
#define OP_SHR 0x08
#define OP_ADDI 0x09
#define OP_XORI 0x0A
#define OP_ANDI 0x0B
#define OP_LOADIN 0x0C
#define OP_LOADFLAG 0x0D
#define OP_EMIT 0x0E
#define OP_HALT 0x0F

#define DOMAIN_EDGE 0x45
#define DOMAIN_MINT 0x4D

#define COND_NONE 0xFF

typedef struct {
    uint8_t cond;
    uint16_t dst;
    uint32_t salt;
    uint8_t tag[6];
} Edge;

typedef struct {
    uint16_t id;
    uint8_t cond_reg;
    uint8_t cond_bit;
    uint16_t poison_dst;
    uint16_t code_len;
    uint8_t code[MAXCODE];
    uint8_t nedges;
    Edge edges[MAXEDGES];
} Block;

static uint8_t g_key[16];
static uint64_t g_nonce;
static Block g_blocks[MAXBLOCKS];
static int g_nblocks;
static uint16_t g_entry;
static uint16_t g_emit_id;
static uint16_t g_reject_id;

static uint64_t rot64(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

static uint64_t siphash24(const uint8_t *key, const uint8_t *in, size_t len) {
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = ((uint64_t)len) << 56;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t m;
        memcpy(&m, in + i, 8);
        v3 ^= m;
        for (int r = 0; r < 2; r++) {
            v0 += v1; v1 = rot64(v1, 13); v1 ^= v0; v0 = rot64(v0, 32);
            v2 += v3; v3 = rot64(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rot64(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rot64(v1, 17); v1 ^= v2; v2 = rot64(v2, 32);
        }
        v0 ^= m;
    }
    int rem = (int)(len - i);
    for (int j = 0; j < rem; j++) b |= ((uint64_t)in[i + j]) << (8 * j);
    v3 ^= b;
    for (int r = 0; r < 2; r++) {
        v0 += v1; v1 = rot64(v1, 13); v1 ^= v0; v0 = rot64(v0, 32);
        v2 += v3; v3 = rot64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rot64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rot64(v1, 17); v1 ^= v2; v2 = rot64(v2, 32);
    }
    v0 ^= b;
    v2 ^= 0xff;
    for (int r = 0; r < 4; r++) {
        v0 += v1; v1 = rot64(v1, 13); v1 ^= v0; v0 = rot64(v0, 32);
        v2 += v3; v3 = rot64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rot64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rot64(v1, 17); v1 ^= v2; v2 = rot64(v2, 32);
    }
    return v0 ^ v1 ^ v2 ^ v3;
}

static void build_tag_msg(uint8_t *buf, uint8_t domain, const uint8_t *data, size_t len) {
    buf[0] = domain;
    memcpy(buf, data, len);
}

static void tag48(const uint8_t *key, uint8_t domain, const uint8_t *data, size_t len, uint8_t out[6]) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    build_tag_msg(buf, domain, data, len);
    uint64_t h = siphash24(key, buf, len);
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)(h >> (8 * i));
}

static void edge_msg(uint16_t src, uint16_t dst, uint8_t cond, uint32_t salt, uint8_t out[9]) {
    out[0] = (uint8_t)src;
    out[1] = (uint8_t)(src >> 8);
    out[2] = (uint8_t)dst;
    out[3] = (uint8_t)(dst >> 8);
    out[4] = cond;
    out[5] = (uint8_t)salt;
    out[6] = (uint8_t)(salt >> 8);
    out[7] = (uint8_t)(salt >> 16);
    out[8] = (uint8_t)(salt >> 24);
}

static uint64_t g_rng;
static uint64_t sm64(void) {
    g_rng += 0x9e3779b97f4a7c15ULL;
    uint64_t z = g_rng;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t g_hw;
static uint64_t hw64(void) {
    g_hw += 0x2545f4914f6cdd1dULL;
    uint64_t z = g_hw;
    z = (z ^ (z >> 33)) * 0xff51afd7ed558ccdULL;
    z = (z ^ (z >> 33)) * 0xc4ceb9fe1a85ec53ULL;
    return z ^ (z >> 33);
}

static void put32(uint8_t *c, int *n, uint32_t v) {
    c[(*n)++] = (uint8_t)v; c[(*n)++] = (uint8_t)(v >> 8);
    c[(*n)++] = (uint8_t)(v >> 16); c[(*n)++] = (uint8_t)(v >> 24);
}

static Block *blk_new(uint16_t id, uint8_t cond_reg, uint8_t cond_bit) {
    Block *b = &g_blocks[g_nblocks++];
    memset(b, 0, sizeof(*b));
    b->id = id;
    b->cond_reg = cond_reg;
    b->cond_bit = cond_bit;
    return b;
}

static void e_r2(Block *b, uint8_t op, uint8_t rd, uint8_t rs) {
    b->code[b->code_len++] = op; b->code[b->code_len++] = rd; b->code[b->code_len++] = rs;
}
static void e_ri(Block *b, uint8_t op, uint8_t rd, uint32_t imm) {
    int n = b->code_len; uint8_t *c = b->code;
    c[n++] = op; c[n++] = rd; put32(c, &n, imm); b->code_len = n;
}
static void e_sh(Block *b, uint8_t op, uint8_t rd, uint8_t sh) {
    b->code[b->code_len++] = op; b->code[b->code_len++] = rd; b->code[b->code_len++] = sh;
}
static void e_load(Block *b, uint8_t rd, uint8_t idx) {
    b->code[b->code_len++] = OP_LOADIN; b->code[b->code_len++] = rd; b->code[b->code_len++] = idx;
}
static void e_op0(Block *b, uint8_t op) { b->code[b->code_len++] = op; }

static uint16_t g_ids[MAXBLOCKS];

static uint16_t fresh_id(int idx) { return g_ids[idx]; }

static uint32_t g_target[NWORD];

static void run_capture(const uint8_t *input);

int build_program(void) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    if (read(fd, g_key, 16) != 16) { close(fd); return -1; }
    uint8_t nb[8];
    if (read(fd, nb, 8) != 8) { close(fd); return -1; }
    uint8_t hwseed[8];
    if (read(fd, hwseed, 8) != 8) { close(fd); return -1; }
    close(fd);
    memcpy(&g_nonce, nb, 8);
    memcpy(&g_hw, hwseed, 8);
    g_rng = g_nonce ^ 0xa5a5a5a5a5a5a5a5ULL;

    int total = 1 + NROUNDS * 3 + 3;
    uint8_t used[65536];
    memset(used, 0, sizeof(used));
    for (int i = 0; i < total; i++) {
        uint16_t id;
        do { id = (uint16_t)(hw64() & 0xffff); } while (id == 0 || used[id]);
        used[id] = 1;
        g_ids[i] = id;
    }

    int idx_entry = 0;
    int idx_round = 1;
    int idx_final = 1 + NROUNDS * 3;
    int idx_emit = idx_final + 1;
    int idx_reject = idx_final + 2;

    g_entry = fresh_id(idx_entry);
    g_emit_id = fresh_id(idx_emit);
    g_reject_id = fresh_id(idx_reject);

    Block *e = blk_new(g_entry, COND_NONE, 0);
    for (int w = 0; w < NWORD; w++) {
        e_ri(e, OP_LDI, (uint8_t)w, 0);
        for (int by = 0; by < 4; by++) {
            e_load(e, 6, (uint8_t)(4 * w + by));
            e_sh(e, OP_ROL, 6, (uint8_t)(8 * by));
            e_r2(e, OP_OR, (uint8_t)w, 6);
        }
    }
    e->edges[0].cond = COND_NONE;
    e->edges[0].dst = fresh_id(idx_round);
    e->nedges = 1;

    for (int r = 0; r < NROUNDS; r++) {
        uint16_t rid = fresh_id(idx_round + r * 3);
        uint16_t aid = fresh_id(idx_round + r * 3 + 1);
        uint16_t bid = fresh_id(idx_round + r * 3 + 2);

        uint8_t s1 = (uint8_t)(1 + (sm64() % 30));
        uint8_t s2 = (uint8_t)(1 + (sm64() % 30));
        uint32_t k1 = (uint32_t)sm64();
        uint32_t k2 = (uint32_t)sm64();
        uint8_t creg = (uint8_t)(sm64() % 4);
        uint8_t cbit = (uint8_t)(sm64() % 32);

        Block *rb = blk_new(rid, creg, cbit);
        e_r2(rb, OP_ADD, 0, 1);
        e_sh(rb, OP_ROL, 0, s1);
        e_r2(rb, OP_XOR, 2, 0);
        e_r2(rb, OP_ADD, 3, 2);
        e_sh(rb, OP_ROL, 3, s2);
        e_r2(rb, OP_XOR, 1, 3);
        e_ri(rb, OP_ADDI, 0, k1);
        e_ri(rb, OP_XORI, 2, k2);

        uint8_t sa = (uint8_t)(1 + (sm64() % 30));
        uint8_t sb = (uint8_t)(1 + (sm64() % 30));
        uint32_t a1 = (uint32_t)sm64();
        uint32_t b1 = (uint32_t)sm64();

        Block *ab = blk_new(aid, COND_NONE, 0);
        e_ri(ab, OP_XORI, 4, a1);
        e_r2(ab, OP_ADD, 5, 4);
        e_sh(ab, OP_ROL, 5, sa);

        Block *bb = blk_new(bid, COND_NONE, 0);
        e_ri(bb, OP_XORI, 4, b1);
        e_r2(bb, OP_ADD, 5, 4);
        e_sh(bb, OP_ROL, 5, sb);

        uint16_t nxt = (r + 1 < NROUNDS) ? fresh_id(idx_round + (r + 1) * 3) : fresh_id(idx_final);
        rb->edges[0].cond = 0; rb->edges[0].dst = aid;
        rb->edges[1].cond = 1; rb->edges[1].dst = bid;
        rb->nedges = 2;
        ab->edges[0].cond = COND_NONE; ab->edges[0].dst = nxt; ab->nedges = 1;
        bb->edges[0].cond = COND_NONE; bb->edges[0].dst = nxt; bb->nedges = 1;
    }

    for (int i = 0; i < g_nblocks; i++) {
        Block *b = &g_blocks[i];
        b->poison_dst = g_reject_id;
        for (int j = 0; j < b->nedges; j++) {
            b->edges[j].salt = (uint32_t)sm64();
            uint8_t msg[9];
            edge_msg(b->id, b->edges[j].dst, b->edges[j].cond, b->edges[j].salt, msg);
            tag48(g_key, DOMAIN_EDGE, msg, 9, b->edges[j].tag);
        }
    }

    uint8_t secret[INLEN];
    for (int i = 0; i < INLEN; i++) secret[i] = (uint8_t)(hw64() & 0xff);
    run_capture(secret);

    Block *fb = blk_new(g_emit_id, COND_NONE, 0);
    e_op0(fb, OP_LOADFLAG);
    e_op0(fb, OP_EMIT);
    e_op0(fb, OP_HALT);
    fb->nedges = 0;
    fb->poison_dst = g_reject_id;

    Block *rj = blk_new(g_reject_id, COND_NONE, 0);
    e_op0(rj, OP_HALT);
    rj->nedges = 0;
    rj->poison_dst = g_reject_id;

    Block *cmp = blk_new(fresh_id(idx_final), 6, 0);
    for (int w = 0; w < NWORD; w++) {
        e_r2(cmp, OP_MOV, 7, (uint8_t)w);
        e_ri(cmp, OP_XORI, 7, g_target[w]);
        if (w == 0) e_r2(cmp, OP_MOV, 6, 7);
        else e_r2(cmp, OP_OR, 6, 7);
    }
    uint8_t shifts[5] = {16, 8, 4, 2, 1};
    for (int s = 0; s < 5; s++) {
        e_r2(cmp, OP_MOV, 7, 6);
        e_sh(cmp, OP_SHR, 7, shifts[s]);
        e_r2(cmp, OP_OR, 6, 7);
    }
    cmp->edges[0].cond = 0; cmp->edges[0].dst = g_emit_id;
    cmp->edges[1].cond = 1; cmp->edges[1].dst = g_reject_id;
    cmp->nedges = 2;
    cmp->poison_dst = g_reject_id;

    for (int i = 0; i < 3; i++) {
        Block *b;
        if (i == 0) b = cmp;
        else if (i == 1) b = fb;
        else b = rj;
        for (int j = 0; j < b->nedges; j++) {
            b->edges[j].salt = (uint32_t)sm64();
            uint8_t msg[9];
            edge_msg(b->id, b->edges[j].dst, b->edges[j].cond, b->edges[j].salt, msg);
            tag48(g_key, DOMAIN_EDGE, msg, 9, b->edges[j].tag);
        }
    }

    uint16_t all_ids[MAXBLOCKS];
    for (int i = 0; i < g_nblocks; i++) all_ids[i] = g_blocks[i].id;

    for (int i = 0; i < g_nblocks; i++) {
        Block *b = &g_blocks[i];
        int base = b->nedges;
        if (base == 0) continue;
        int add = 0;
        Edge extra[MAXEDGES];
        for (int j = 0; j < base && b->nedges + add < MAXEDGES; j++) {
            int npoison = 1 + (int)(sm64() % 2);
            for (int p = 0; p < npoison && b->nedges + add < MAXEDGES; p++) {
                Edge pe;
                pe.cond = b->edges[j].cond;
                uint16_t d;
                do { d = all_ids[sm64() % g_nblocks]; } while (d == b->edges[j].dst);
                pe.dst = d;
                pe.salt = (uint32_t)sm64();
                for (int t = 0; t < 6; t++) pe.tag[t] = (uint8_t)(sm64() & 0xff);
                extra[add++] = pe;
            }
        }
        for (int j = 0; j < add; j++) b->edges[b->nedges + j] = extra[j];
        b->nedges += add;

        for (int a = b->nedges - 1; a > 0; a--) {
            int s = (int)(sm64() % (a + 1));
            Edge tmp = b->edges[a]; b->edges[a] = b->edges[s]; b->edges[s] = tmp;
        }
    }

    return 0;
}

static Block *find_block(uint16_t id) {
    for (int i = 0; i < g_nblocks; i++) if (g_blocks[i].id == id) return &g_blocks[i];
    return NULL;
}

static uint32_t rol32(uint32_t x, int b) { b &= 31; if (!b) return x; return (x << b) | (x >> (32 - b)); }

static int exec_block(Block *b, uint32_t *r, const uint8_t *input, uint8_t *flagbuf, int *emitted) {
    int pc = 0;
    while (pc < b->code_len) {
        uint8_t op = b->code[pc++];
        if (op == OP_LDI) { uint8_t rd = b->code[pc++]; uint32_t v; memcpy(&v, b->code + pc, 4); pc += 4; r[rd] = v; }
        else if (op == OP_MOV) { uint8_t rd = b->code[pc++], rs = b->code[pc++]; r[rd] = r[rs]; }
        else if (op == OP_ADD) { uint8_t rd = b->code[pc++], rs = b->code[pc++]; r[rd] += r[rs]; }
        else if (op == OP_XOR) { uint8_t rd = b->code[pc++], rs = b->code[pc++]; r[rd] ^= r[rs]; }
        else if (op == OP_AND) { uint8_t rd = b->code[pc++], rs = b->code[pc++]; r[rd] &= r[rs]; }
        else if (op == OP_OR) { uint8_t rd = b->code[pc++], rs = b->code[pc++]; r[rd] |= r[rs]; }
        else if (op == OP_ROL) { uint8_t rd = b->code[pc++], sh = b->code[pc++]; r[rd] = rol32(r[rd], sh); }
        else if (op == OP_SHR) { uint8_t rd = b->code[pc++], sh = b->code[pc++]; r[rd] = (sh >= 32) ? 0 : (r[rd] >> sh); }
        else if (op == OP_ADDI) { uint8_t rd = b->code[pc++]; uint32_t v; memcpy(&v, b->code + pc, 4); pc += 4; r[rd] += v; }
        else if (op == OP_XORI) { uint8_t rd = b->code[pc++]; uint32_t v; memcpy(&v, b->code + pc, 4); pc += 4; r[rd] ^= v; }
        else if (op == OP_ANDI) { uint8_t rd = b->code[pc++]; uint32_t v; memcpy(&v, b->code + pc, 4); pc += 4; r[rd] &= v; }
        else if (op == OP_LOADIN) { uint8_t rd = b->code[pc++], ix = b->code[pc++]; r[rd] = (ix < INLEN) ? input[ix] : 0; }
        else if (op == OP_LOADFLAG) {
            const char *f = getenv("FLAG");
            if (!f) f = "unavailable";
            memset(flagbuf, 0, 128);
            strncpy((char *)flagbuf, f, 127);
        }
        else if (op == OP_EMIT) { *emitted = 1; }
        else if (op == OP_HALT) { return 1; }
    }
    return 0;
}

static uint16_t pick_edge(Block *b, uint32_t *r) {
    uint8_t cval;
    if (b->cond_reg == COND_NONE) cval = COND_NONE;
    else cval = (uint8_t)((r[b->cond_reg] >> b->cond_bit) & 1);
    for (int i = 0; i < b->nedges; i++) {
        if (b->edges[i].cond != cval) continue;
        uint8_t msg[9], tg[6];
        edge_msg(b->id, b->edges[i].dst, b->edges[i].cond, b->edges[i].salt, msg);
        tag48(g_key, DOMAIN_EDGE, msg, 9, tg);
        if (memcmp(tg, b->edges[i].tag, 6) == 0) return b->edges[i].dst;
    }
    return b->poison_dst;
}

static void run_capture(const uint8_t *input) {
    uint32_t r[NREG];
    memset(r, 0, sizeof(r));
    uint16_t cur = g_entry;
    uint16_t finalid = fresh_id(1 + NROUNDS * 3);
    uint8_t flagbuf[128];
    int emitted = 0;
    int steps = 0;
    while (steps++ < STEP_CAP) {
        if (cur == finalid) {
            for (int w = 0; w < NWORD; w++) g_target[w] = r[w];
            return;
        }
        Block *b = find_block(cur);
        if (!b) return;
        int halt = exec_block(b, r, input, flagbuf, &emitted);
        if (halt || b->nedges == 0) return;
        cur = pick_edge(b, r);
    }
}

static int run_vm(const uint8_t *input, char *out, int outcap) {
    uint32_t r[NREG];
    memset(r, 0, sizeof(r));
    uint16_t cur = g_entry;
    uint8_t flagbuf[128];
    memset(flagbuf, 0, sizeof(flagbuf));
    int emitted = 0;
    int steps = 0;
    while (steps++ < STEP_CAP) {
        Block *b = find_block(cur);
        if (!b) break;
        int halt = exec_block(b, r, input, flagbuf, &emitted);
        if (emitted) { snprintf(out, outcap, "%s", (char *)flagbuf); return 1; }
        if (halt || b->nedges == 0) break;
        cur = pick_edge(b, r);
    }
    snprintf(out, outcap, "denied");
    return 0;
}

static void ser_u16(uint8_t **p, uint16_t v) { (*p)[0] = (uint8_t)v; (*p)[1] = (uint8_t)(v >> 8); *p += 2; }
static void ser_u32(uint8_t **p, uint32_t v) { for (int i = 0; i < 4; i++) (*p)[i] = (uint8_t)(v >> (8 * i)); *p += 4; }

static int serialize(uint8_t *buf) {
    uint8_t *p = buf;
    memcpy(p, "CSGN", 4); p += 4;
    ser_u16(&p, 2);
    ser_u16(&p, (uint16_t)g_nblocks);
    ser_u16(&p, g_entry);
    memcpy(p, &g_nonce, 8); p += 8;
    for (int i = 0; i < g_nblocks; i++) {
        Block *b = &g_blocks[i];
        ser_u16(&p, b->id);
        *p++ = b->cond_reg;
        *p++ = b->cond_bit;
        ser_u16(&p, b->poison_dst);
        ser_u16(&p, b->code_len);
        memcpy(p, b->code, b->code_len); p += b->code_len;
        *p++ = b->nedges;
        for (int j = 0; j < b->nedges; j++) {
            *p++ = b->edges[j].cond;
            ser_u16(&p, b->edges[j].dst);
            ser_u32(&p, b->edges[j].salt);
            memcpy(p, b->edges[j].tag, 6); p += 6;
        }
    }
    return (int)(p - buf);
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int unhex(const char *s, uint8_t *out, int cap) {
    int n = 0;
    while (s[0] && s[1]) {
        if (s[0] == '\n' || s[0] == '\r' || s[0] == ' ') { s++; continue; }
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0) return -1;
        if (n >= cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (build_program() != 0) { printf("boot error\n"); return 1; }

    printf("Countersign attestation core v2 ready.\n");
    printf("commands: GET | NONCE | MINT <hex<=16> | RUN <hex 24>\n");

    static uint8_t blob[1 << 18];
    char line[8192];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "GET", 3) == 0 && (line[3] == '\n' || line[3] == '\r' || line[3] == 0)) {
            int n = serialize(blob);
            for (int i = 0; i < n; i++) printf("%02x", blob[i]);
            printf("\n");
        } else if (strncmp(line, "NONCE", 5) == 0) {
            printf("%016llx\n", (unsigned long long)g_nonce);
        } else if (strncmp(line, "MINT ", 5) == 0) {
            uint8_t data[64];
            int n = unhex(line + 5, data, sizeof(data));
            if (n < 0 || n > 16) { printf("bad\n"); continue; }
            uint8_t tg[6];
            tag48(g_key, DOMAIN_MINT, data, n, tg);
            for (int i = 0; i < 6; i++) printf("%02x", tg[i]);
            printf("\n");
        } else if (strncmp(line, "RUN ", 4) == 0) {
            uint8_t in[64];
            int n = unhex(line + 4, in, sizeof(in));
            if (n != INLEN) { printf("need 24 bytes\n"); continue; }
            char out[256];
            run_vm(in, out, sizeof(out));
            printf("%s\n", out);
        } else if (strncmp(line, "QUIT", 4) == 0) {
            break;
        } else {
            printf("?\n");
        }
    }
    return 0;
}
