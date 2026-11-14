#include "wav.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *in, size_t inlen, unsigned char **out, size_t *outlen) {
    unsigned char *buf = malloc(inlen / 4 * 3 + 4);
    if (!buf) return -1;
    size_t o = 0;
    int acc = 0, nbits = 0;
    for (size_t i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i];
        if (c == '=' ) break;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = b64val(c);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            buf[o++] = (unsigned char)((acc >> nbits) & 0xFF);
        }
    }
    *out = buf;
    *outlen = o;
    return 0;
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

int wav_read_mono24(const unsigned char *buf, size_t len, double **samples, size_t *count) {
    if (len < 12) return -1;
    if (memcmp(buf, "RIFF", 4) != 0 || memcmp(buf + 8, "WAVE", 4) != 0) return -1;
    size_t pos = 12;
    uint16_t channels = 0, bits = 0;
    uint32_t rate = 0;
    const unsigned char *data = NULL;
    uint32_t datalen = 0;
    while (pos + 8 <= len) {
        const unsigned char *id = buf + pos;
        uint32_t sz = rd32(buf + pos + 4);
        pos += 8;
        if (pos + sz > len) sz = (uint32_t)(len - pos);
        if (memcmp(id, "fmt ", 4) == 0 && sz >= 16) {
            channels = rd16(buf + pos + 2);
            rate = rd32(buf + pos + 4);
            bits = rd16(buf + pos + 14);
        } else if (memcmp(id, "data", 4) == 0) {
            data = buf + pos;
            datalen = sz;
        }
        pos += sz;
        if (sz & 1) pos += 1;
    }
    if (!data || channels != 1 || bits != 24 || rate != INPUT_SR) return -1;
    size_t n = datalen / 3;
    if (n == 0) return -1;
    if (n > MAX_SAMPLES) n = MAX_SAMPLES;
    double *s = malloc(sizeof(double) * n);
    if (!s) return -1;
    for (size_t i = 0; i < n; i++) {
        int32_t v = (int32_t)data[i * 3] | ((int32_t)data[i * 3 + 1] << 8) | ((int32_t)data[i * 3 + 2] << 16);
        if (v & 0x800000) v |= (int32_t)0xFF000000;
        s[i] = (double)v / 8388608.0;
    }
    *samples = s;
    *count = n;
    return 0;
}
