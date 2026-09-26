#include "codec.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct effect_ctx;
typedef void (*process_fn)(struct effect_ctx *);

typedef struct effect_ctx {
    int frames;
    int last_len;
} effect_ctx_t;

typedef struct effect_chain {
    process_fn process;
    double wet;
    double dry;
    int32_t taps;
    int32_t mode;
    uint8_t state[16];
} effect_chain_t;

typedef struct cal_region {
    uint8_t data[32];
} cal_region_t;

static effect_chain_t *g_chain;
static cal_region_t *g_region;
static int g_bound;
static effect_ctx_t g_ctx;

static void factory_diag(effect_ctx_t *ctx) {
    (void)ctx;
    const char *flag = getenv("FLAG");
    printf("FACTORY DIAG UNLOCKED\n");
    if (flag)
        printf("FLAG: %s\n", flag);
    else
        printf("FLAG: unavailable\n");
    fflush(stdout);
}

static void passthrough(effect_ctx_t *ctx) {
    ctx->frames++;
}

void codec_init(void) {
    g_region = malloc(sizeof(cal_region_t));
    g_chain = malloc(sizeof(effect_chain_t));

    g_chain->process = passthrough;
    g_chain->wet = 1.0;
    g_chain->dry = 0.0;
    g_chain->taps = 4;
    g_chain->mode = 0;
    memset(g_chain->state, 0, sizeof(g_chain->state));

    uint64_t sig = (uint64_t)(uintptr_t)factory_diag;
    uint64_t hp = (uint64_t)(uintptr_t)g_chain;
    memcpy(g_region->data, &sig, 8);
    memcpy(g_region->data + 8, &hp, 8);
    memset(g_region->data + 16, 0x2e, 16);

    g_bound = 0;
    g_ctx.frames = 0;
    g_ctx.last_len = 0;
}

static void echo_region(void) {
    printf("CAL ECHO: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", g_region->data[i]);
    printf("\n");
}

void codec_handle(const unsigned char *payload, int plen) {
    int i = 0;
    while (i + 1 < plen) {
        int type = payload[i];
        int len = payload[i + 1];
        const unsigned char *val = payload + i + 2;
        if (i + 2 + len > plen) break;
        if (type == OPCODE_SELECT_PROFILE) {
            if (len >= 1 && val[0] == PROFILE_CAL_REGION) {
                g_bound = 1;
                printf("PROFILE SELECTED: region 0x%02x\n", val[0]);
                echo_region();
            } else {
                printf("PROFILE REJECTED\n");
            }
        } else if (type == OPCODE_SET_CAL_VECTOR) {
            if (!g_bound) {
                printf("NO PROFILE BOUND\n");
            } else if (len >= 1) {
                int cnt = val[0];
                int avail = plen - (i + 2) - 1;
                if (cnt * 2 <= avail) {
                    memcpy(g_region->data, val + 1, (size_t)cnt * 2);
                    printf("CAL VECTOR WRITTEN: count=%d\n", cnt);
                } else {
                    printf("CAL VECTOR TRUNCATED\n");
                }
            }
        } else if (type == OPCODE_DEBUG_PING) {
            printf("PONG\n");
        } else {
            printf("UNKNOWN OPCODE 0x%02x\n", type);
        }
        i += 2 + len;
    }
    fflush(stdout);
}

void codec_run_effects(void) {
    g_ctx.frames++;
    g_chain->process(&g_ctx);
}
