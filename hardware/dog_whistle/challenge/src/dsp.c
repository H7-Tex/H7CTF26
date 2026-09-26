#include "dsp.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef struct {
    double b0, b1, b2, a1, a2;
} biquad_t;

static const biquad_t LPF_SOS[3] = {
    {6.56583801739415090e-05, 1.31316760347883018e-04, 6.56583801739415090e-05,
     -1.25681248197591589e+00, 4.01327550470669314e-01},
    {1.0, 2.0, 1.0, -1.36640781666419953e+00, 5.23524747032796389e-01},
    {1.0, 2.0, 1.0, -1.60950144797582850e+00, 7.94570593399138381e-01},
};

typedef struct {
    int type;
    double f0, q, gain_db;
} eq_band_t;

static eq_band_t g_eq_bands[8];
static int g_eq_loaded = -1;
static int g_eq_count = 0;

static int parse_type(const char *s) {
    if (strcmp(s, "peak") == 0) return 0;
    if (strcmp(s, "notch") == 0) return 1;
    if (strcmp(s, "lowshelf") == 0) return 2;
    if (strcmp(s, "highshelf") == 0) return 3;
    return 0;
}

static void load_eq(void) {
    g_eq_loaded = 1;
    g_eq_count = 0;
    const char *path = getenv("EQ_CFG");
    if (!path) path = "eq.cfg";
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f) && g_eq_count < 8) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char t[32];
        double f0, q, g;
        if (sscanf(line, "%31s %lf %lf %lf", t, &f0, &q, &g) == 4) {
            g_eq_bands[g_eq_count].type = parse_type(t);
            g_eq_bands[g_eq_count].f0 = f0;
            g_eq_bands[g_eq_count].q = q;
            g_eq_bands[g_eq_count].gain_db = g;
            g_eq_count++;
        }
    }
    fclose(f);
}

static void design_peak(const eq_band_t *b, biquad_t *out) {
    double A = pow(10.0, b->gain_db / 40.0);
    double w0 = 2.0 * M_PI * b->f0 / INPUT_SR;
    double cw = cos(w0), sw = sin(w0);
    double alpha = sw / (2.0 * b->q);
    double a0, a1, a2, b0, b1, b2;
    if (b->type == 1) {
        b0 = 1.0; b1 = -2.0 * cw; b2 = 1.0;
        a0 = 1.0 + alpha; a1 = -2.0 * cw; a2 = 1.0 - alpha;
    } else if (b->type == 2) {
        double s = 2.0 * sqrt(A) * alpha;
        b0 = A * ((A + 1) - (A - 1) * cw + s);
        b1 = 2 * A * ((A - 1) - (A + 1) * cw);
        b2 = A * ((A + 1) - (A - 1) * cw - s);
        a0 = (A + 1) + (A - 1) * cw + s;
        a1 = -2 * ((A - 1) + (A + 1) * cw);
        a2 = (A + 1) + (A - 1) * cw - s;
    } else if (b->type == 3) {
        double s = 2.0 * sqrt(A) * alpha;
        b0 = A * ((A + 1) + (A - 1) * cw + s);
        b1 = -2 * A * ((A - 1) + (A + 1) * cw);
        b2 = A * ((A + 1) + (A - 1) * cw - s);
        a0 = (A + 1) - (A - 1) * cw + s;
        a1 = 2 * ((A - 1) - (A + 1) * cw);
        a2 = (A + 1) - (A - 1) * cw - s;
    } else {
        b0 = 1 + alpha * A; b1 = -2 * cw; b2 = 1 - alpha * A;
        a0 = 1 + alpha / A; a1 = -2 * cw; a2 = 1 - alpha / A;
    }
    out->b0 = b0 / a0; out->b1 = b1 / a0; out->b2 = b2 / a0;
    out->a1 = a1 / a0; out->a2 = a2 / a0;
}

static void run_biquad(const biquad_t *bq, double *x, size_t n) {
    double z1 = 0.0, z2 = 0.0;
    for (size_t i = 0; i < n; i++) {
        double in = x[i];
        double y = bq->b0 * in + z1;
        z1 = bq->b1 * in - bq->a1 * y + z2;
        z2 = bq->b2 * in - bq->a2 * y;
        x[i] = y;
    }
}

void eq_apply(double *x, size_t n) {
    if (g_eq_loaded < 0) load_eq();
    for (int i = 0; i < g_eq_count; i++) {
        if (g_eq_bands[i].gain_db == 0.0 && g_eq_bands[i].type == 0) continue;
        biquad_t bq;
        design_peak(&g_eq_bands[i], &bq);
        run_biquad(&bq, x, n);
    }
}

static void run_lpf(double *x, size_t n) {
    for (int s = 0; s < 3; s++) {
        double z1 = 0.0, z2 = 0.0;
        const biquad_t *bq = &LPF_SOS[s];
        for (size_t i = 0; i < n; i++) {
            double in = x[i];
            double y = bq->b0 * in + z1;
            z1 = bq->b1 * in - bq->a1 * y + z2;
            z2 = bq->b2 * in - bq->a2 * y;
            x[i] = y;
        }
    }
}

size_t antialias_decimate(const double *x, size_t n, double *out) {
    double *tmp = malloc(sizeof(double) * n);
    if (!tmp) return 0;
    memcpy(tmp, x, sizeof(double) * n);
    run_lpf(tmp, n);
    size_t o = 0;
    for (size_t i = 0; i < n; i += DECIM) out[o++] = tmp[i];
    free(tmp);
    return o;
}

void mic_nonlinear(double *x, size_t n) {
    for (size_t i = 0; i < n; i++) {
        double g = MIC_GAIN * x[i];
        x[i] = POLY_A1 * g + POLY_A2 * g * g + POLY_A3 * g * g * g;
    }
}

static double goertzel(const double *x, size_t n, double freq) {
    double k = 2.0 * cos(2.0 * M_PI * freq / CODEC_SR);
    double s0, s1 = 0.0, s2 = 0.0;
    for (size_t i = 0; i < n; i++) {
        s0 = x[i] + k * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    return s1 * s1 + s2 * s2 - k * s1 * s2;
}

static int read_symbol(const double *codec, size_t n, size_t sym) {
    size_t start = SYM_LEAD + sym * SYM_LEN;
    if (start + SYM_LEN > n) return -1;
    int best = -1;
    double bestmag = -1.0;
    for (int t = 0; t < TONE_COUNT; t++) {
        double f = TONE_BASE + t * TONE_STEP;
        double m = goertzel(codec + start, SYM_LEN, f);
        if (m > bestmag) { bestmag = m; best = t; }
    }
    return best;
}

int demod_frame(const double *codec, size_t n, unsigned char *payload, int *plen) {
    int nibs[600];
    int count = 0;
    for (size_t sym = 0; count < 600; sym++) {
        int v = read_symbol(codec, n, sym);
        if (v < 0) break;
        nibs[count++] = v;
    }
    int nbytes = count / 2;
    if (nbytes < 4) return -1;
    unsigned char bytes[300];
    for (int i = 0; i < nbytes && i < 300; i++)
        bytes[i] = (unsigned char)((nibs[2 * i] << 4) | nibs[2 * i + 1]);
    if (bytes[0] != PREAMBLE0 || bytes[1] != PREAMBLE1) return -1;
    int L = bytes[2];
    if (L < 0 || 3 + L + 1 > nbytes) return -1;
    unsigned char cs = (unsigned char)L;
    for (int i = 0; i < L; i++) cs ^= bytes[3 + i];
    if (cs != bytes[3 + L]) return -1;
    memcpy(payload, bytes + 3, L);
    *plen = L;
    return 0;
}

int interlock_engineering(const double *post_eq, size_t n) {
    double *codec = malloc(sizeof(double) * (n / DECIM + 4));
    if (!codec) return 0;
    size_t cn = antialias_decimate(post_eq, n, codec);
    unsigned char payload[300];
    int plen = 0;
    int found = 0;
    if (demod_frame(codec, cn, payload, &plen) == 0) {
        int i = 0;
        while (i + 1 < plen) {
            int type = payload[i];
            int len = payload[i + 1];
            if (type == OPCODE_SELECT_PROFILE || type == OPCODE_SET_CAL_VECTOR) {
                found = 1;
                break;
            }
            i += 2 + len;
        }
    }
    free(codec);
    return found;
}
