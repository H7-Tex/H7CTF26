#ifndef ARIA_DSP_H
#define ARIA_DSP_H

#include <stddef.h>

void eq_apply(double *x, size_t n);
size_t antialias_decimate(const double *x, size_t n, double *out);
void mic_nonlinear(double *x, size_t n);
int demod_frame(const double *codec, size_t n, unsigned char *payload, int *plen);
int interlock_engineering(const double *post_eq, size_t n);

#endif
