/* Cipherlock - a constraint-based key controller.
 * The 16-byte key must satisfy a mix of XOR couplings, byte products (mod 256) and rotate+add
 * relations. On a valid key it derives AES-128 from MD5(key) and prints the flag.
 * build: gcc cipherlock.c -o cipherlock -lcrypto -Os -s
 */
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include "cipherlock_data.h"

static unsigned char rol8(unsigned char v, int r) { return (unsigned char)((v << r) | (v >> (8 - r))); }

static int check(const unsigned char *k) {
    int ok = 1;
    for (int i = 0; i < N; i++)
        if ((unsigned char)(k[i] ^ k[(i + 3) % N]) != CX[i]) ok = 0;
    for (int i = 0; i < N / 2; i++)
        if ((unsigned char)((unsigned int)k[2 * i] * (unsigned int)k[2 * i + 1]) != CY[i]) ok = 0;
    for (int i = 0; i < N; i++)
        if ((unsigned char)(rol8(k[i], 3) + k[(i + 5) % N]) != CZ[i]) ok = 0;
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
        printf("cipherlock: denied\n");
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
    printf("cipherlock: open. %s\n", out);
    return 0;
}
