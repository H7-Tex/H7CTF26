/* Warden - satellite modem firmware license validator.
 * A tiny stack VM runs the embedded license-check bytecode; on a valid 16-char license it
 * derives AES-128 from MD5(license) and decrypts the provisioning blob (the flag).
 * build: gcc warden.c -o warden -lcrypto -Os -s
 */
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include "warden_data.h"

static unsigned char st[256];
static int sp;
static void push(unsigned char v) { st[sp++] = v; }
static unsigned char pop(void) { return st[--sp]; }
static unsigned char rol8(unsigned char v, int r) { return (unsigned char)((v << r) | (v >> (8 - r))); }

/* returns 1 if the license passes every check in the bytecode */
static int run_vm(const unsigned char *in) {
    int pc = 0, ok = 1;
    sp = 0;
    while (pc < BYTECODE_LEN) {
        unsigned char op = BYTECODE[pc++];
        if (op == 0x00) break;                      /* HALT */
        else if (op == 0x01) push(in[BYTECODE[pc++]]);            /* PUSH_INPUT idx */
        else if (op == 0x02) push(BYTECODE[pc++]);               /* PUSH_IMM b */
        else if (op == 0x03) push(pop() ^ pop());                /* XOR */
        else if (op == 0x04) push((unsigned char)(pop() + pop())); /* ADD */
        else if (op == 0x05) { int r = BYTECODE[pc++]; push(rol8(pop(), r)); } /* ROL n */
        else if (op == 0x06) { unsigned char t = BYTECODE[pc++]; if (pop() != t) ok = 0; } /* CMP_IMM */
        else return 0;
    }
    return ok;
}

int main(int argc, char **argv) {
    unsigned char lic[17] = {0};
    if (argc > 1) {
        strncpy((char *)lic, argv[1], 16);
    } else {
        printf("license key: ");
        if (!fgets((char *)lic, sizeof lic, stdin)) return 1;
        lic[strcspn((char *)lic, "\r\n")] = 0;
    }
    if (strlen((char *)lic) != 16 || !run_vm(lic)) {
        printf("license rejected\n");
        return 1;
    }
    unsigned char key[16];
    MD5(lic, 16, key);
    unsigned char out[FLAGBLOB_LEN + 1] = {0};
    AES_KEY ak;
    AES_set_decrypt_key(key, 128, &ak);
    unsigned char iv[16] = {0};
    AES_cbc_encrypt(FLAGBLOB, out, FLAGBLOB_LEN, &ak, iv, AES_DECRYPT);
    int n = FLAGBLOB_LEN - out[FLAGBLOB_LEN - 1];    /* strip PKCS7 */
    if (n > 0 && n <= FLAGBLOB_LEN) out[n] = 0;
    printf("license accepted. provisioning: %s\n", out);
    return 0;
}
