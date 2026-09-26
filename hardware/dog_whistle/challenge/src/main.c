#include "config.h"
#include "wav.h"
#include "dsp.h"
#include "codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void banner(void) {
    printf("aria smart-speaker diagnostic bridge\n");
    printf("firmware r7.2 acoustic control port\n");
    printf("submit one base64 wav capture per line (mono 24-bit %d hz, max %d s)\n",
           INPUT_SR, MAX_SECONDS);
    printf("capture budget: %d\n", CAP_BUDGET);
    printf("----\n");
    fflush(stdout);
}

static int process_capture(const char *line, size_t linelen) {
    unsigned char *raw = NULL;
    size_t rawlen = 0;
    if (base64_decode(line, linelen, &raw, &rawlen) != 0) {
        printf("CAPTURE REJECTED: decode error\n");
        return 0;
    }
    double *samples = NULL;
    size_t n = 0;
    if (wav_read_mono24(raw, rawlen, &samples, &n) != 0) {
        printf("CAPTURE REJECTED: expected mono 24-bit %d hz wav\n", INPUT_SR);
        free(raw);
        return 0;
    }
    free(raw);

    eq_apply(samples, n);

    if (interlock_engineering(samples, n)) {
        printf("SAFETY LOCKOUT: engineering tone signature present in control band\n");
        printf("capture quarantined\n");
        free(samples);
        return 1;
    }

    mic_nonlinear(samples, n);

    double *codec = malloc(sizeof(double) * (n / DECIM + 4));
    size_t cn = antialias_decimate(samples, n, codec);
    free(samples);

    unsigned char payload[300];
    int plen = 0;
    if (demod_frame(codec, cn, payload, &plen) == 0) {
        codec_handle(payload, plen);
    } else {
        printf("no command frame recovered\n");
    }
    free(codec);

    codec_run_effects();
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    codec_init();
    banner();

    char *line = NULL;
    size_t cap = 0;
    int budget = CAP_BUDGET;
    while (budget > 0) {
        ssize_t r = getline(&line, &cap, stdin);
        if (r < 0) break;
        while (r > 0 && (line[r - 1] == '\n' || line[r - 1] == '\r')) line[--r] = 0;
        if (r == 0) continue;
        int used = process_capture(line, (size_t)r);
        printf("----\n");
        fflush(stdout);
        if (used) budget--;
    }
    printf("session closed\n");
    free(line);
    return 0;
}
