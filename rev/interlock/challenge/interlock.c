/* Interlock - a coupled-tumbler license controller.
 * The 16-byte key is valid iff it satisfies a system of linear congruences A*key == B (mod 256).
 * On a valid key it derives AES-128 from MD5(key) and decrypts the unlock token (the flag).
 * build: gcc interlock.c -o interlock -lcrypto -Os -s
 */
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include "interlock_data.h"

static int check(const unsigned char *k) {
    int ok = 1;
    for (int i = 0; i < N; i++) {
        unsigned int acc = 0;
        for (int j = 0; j < N; j++)
            acc += (unsigned int)A[i][j] * (unsigned int)k[j];
        if ((acc & 0xff) != B[i])
            ok = 0;
    }
    return ok;
}

int main(int argc, char **argv) {
    unsigned char key[17] = {0};
    if (argc > 1) {
        strncpy((char *)key, argv[1], 16);
    } else {
        printf("key: ");
        if (!fgets((char *)key, sizeof key, stdin)) return 1;
        key[strcspn((char *)key, "\r\n")] = 0;
    }
    if (strlen((char *)key) != 16 || !check(key)) {
        printf("interlock: rejected\n");
        return 1;
    }
    unsigned char aeskey[16];
    MD5(key, 16, aeskey);
    unsigned char out[FLAGBLOB_LEN + 1] = {0};
    AES_KEY ak;
    AES_set_decrypt_key(aeskey, 128, &ak);
    unsigned char iv[16] = {0};
    AES_cbc_encrypt(FLAGBLOB, out, FLAGBLOB_LEN, &ak, iv, AES_DECRYPT);
    int n = FLAGBLOB_LEN - out[FLAGBLOB_LEN - 1];
    if (n > 0 && n <= FLAGBLOB_LEN) out[n] = 0;
    printf("interlock: released. token: %s\n", out);
    return 0;
}
