#ifndef ARIA_CODEC_H
#define ARIA_CODEC_H

void codec_init(void);
void codec_handle(const unsigned char *payload, int plen);
void codec_run_effects(void);

#endif
