#ifndef ARIA_WAV_H
#define ARIA_WAV_H

#include <stddef.h>

int base64_decode(const char *in, size_t inlen, unsigned char **out, size_t *outlen);
int wav_read_mono24(const unsigned char *buf, size_t len, double **samples, size_t *count);

#endif
