#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

enum {
    OP_HALT = 0, OP_LDS, OP_LDI, OP_MOV, OP_XOR, OP_ADD, OP_MUL,
    OP_AND, OP_OR, OP_ROL, OP_SBOX, OP_ASSERT, OP_ANDI, OP_XORI
};

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rol32(uint32_t v, unsigned c) {
    c &= 31;
    if (!c) return v;
    return (v << c) | (v >> (32 - c));
}

static uint8_t *slurp(const char *path, long *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*len);
    if (fread(b, 1, *len, f) != (size_t)*len) { fclose(f); free(b); return NULL; }
    fclose(f);
    return b;
}

static int hexbyte(const char *s) {
    int hi = s[0], lo = s[1];
    hi = (hi <= '9') ? hi - '0' : (hi | 32) - 'a' + 10;
    lo = (lo <= '9') ? lo - '0' : (lo | 32) - 'a' + 10;
    return (hi << 4) | lo;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <shard> <key16hex> [table]\n", argv[0]);
        return 2;
    }
    long slen = 0;
    uint8_t *blob = slurp(argv[1], &slen);
    if (!blob || slen < 50 || memcmp(blob, "KSHD", 4) != 0) {
        fprintf(stderr, "bad shard\n");
        return 2;
    }
    uint8_t flags = blob[5];
    uint16_t perm_len = (uint16_t)(blob[8] | (blob[9] << 8));
    uint16_t prog_len = (uint16_t)(blob[10] | (blob[11] << 8));
    const uint8_t *perm_stored = blob + 50;
    const uint8_t *sbox = perm_stored + perm_len;
    const uint8_t *prog = sbox + 256;
    if (50 + perm_len + 256 + prog_len > slen) {
        fprintf(stderr, "truncated shard\n");
        return 2;
    }

    uint8_t dec[256];
    if (flags & 1) {
        memcpy(dec, perm_stored, 256);
    } else {
        if (argc < 4) {
            fprintf(stderr, "shard requires an external table\n");
            return 2;
        }
        long plen = 0;
        uint8_t *pb = slurp(argv[3], &plen);
        if (!pb || plen < 256) {
            fprintf(stderr, "bad table\n");
            return 2;
        }
        memcpy(dec, pb, 256);
        free(pb);
    }

    uint8_t sec[8];
    for (int i = 0; i < 8; i++) sec[i] = hexbyte(argv[2] + i * 2);

    uint32_t regs[8];
    memset(regs, 0, sizeof(regs));
    int ip = 0;
    while (ip < prog_len) {
        int op = dec[prog[ip]];
        if (op == OP_HALT) break;
        switch (op) {
        case OP_LDS: regs[prog[ip + 1]] = sec[prog[ip + 2]]; ip += 3; break;
        case OP_LDI: regs[prog[ip + 1]] = rd32(prog + ip + 2); ip += 6; break;
        case OP_MOV: regs[prog[ip + 1]] = regs[prog[ip + 2]]; ip += 3; break;
        case OP_XOR: regs[prog[ip + 1]] ^= regs[prog[ip + 2]]; ip += 3; break;
        case OP_ADD: regs[prog[ip + 1]] += regs[prog[ip + 2]]; ip += 3; break;
        case OP_MUL: regs[prog[ip + 1]] *= regs[prog[ip + 2]]; ip += 3; break;
        case OP_AND: regs[prog[ip + 1]] &= regs[prog[ip + 2]]; ip += 3; break;
        case OP_OR: regs[prog[ip + 1]] |= regs[prog[ip + 2]]; ip += 3; break;
        case OP_ROL: regs[prog[ip + 1]] = rol32(regs[prog[ip + 1]], prog[ip + 2]); ip += 3; break;
        case OP_SBOX: regs[prog[ip + 1]] = sbox[regs[prog[ip + 2]] & 0xff]; ip += 3; break;
        case OP_ANDI: regs[prog[ip + 1]] &= rd32(prog + ip + 2); ip += 6; break;
        case OP_XORI: regs[prog[ip + 1]] ^= rd32(prog + ip + 2); ip += 6; break;
        case OP_ASSERT:
            if (regs[prog[ip + 1]] != rd32(prog + ip + 2)) {
                printf("FAIL\n");
                free(blob);
                return 1;
            }
            ip += 6;
            break;
        default:
            fprintf(stderr, "bad opcode\n");
            free(blob);
            return 2;
        }
    }
    printf("OK\n");
    free(blob);
    return 0;
}
