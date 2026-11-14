/* ProtonVPN_x64final.exe - the quarantined sample recovered from the Avast chest.
 * Benign file-encryptor modeling the real ransomware's crypto for the RE exercise:
 * legacy Windows CryptoAPI, key = CryptDeriveKey(CALG_AES_128) from MD5(""), AES-128-CBC
 * with a zero IV and PKCS7 padding (CryptEncrypt Final=TRUE). Reversing this reveals the
 * decryption profile for the E:\ files. Compile: x86_64-w64-mingw32-gcc sample.c -o
 * ProtonVPN_x64final.exe -ladvapi32
 */
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

static HCRYPTKEY derive_key(HCRYPTPROV hProv) {
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    BYTE iv[16] = {0};
    DWORD mode = CRYPT_MODE_CBC;
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, (const BYTE *)"", 0, 0);         /* empty password */
    CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey); /* MD5 -> AES-128 key */
    CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&mode, 0);    /* CBC */
    CryptSetKeyParam(hKey, KP_IV, iv, 0);                 /* zero IV */
    CryptDestroyHash(hHash);
    return hKey;
}

static int encrypt_file(HCRYPTKEY hKey, const char *path) {
    char outp[MAX_PATH];
    HANDLE hf = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 1;
    DWORD sz = GetFileSize(hf, NULL);
    DWORD cap = sz + 16;
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cap);
    DWORD got = 0;
    ReadFile(hf, buf, sz, &got, NULL);
    CloseHandle(hf);
    DWORD len = got;
    CryptEncrypt(hKey, 0, TRUE, 0, buf, &len, cap);       /* Final=TRUE -> PKCS7 pad */
    snprintf(outp, sizeof outp, "%s.enc", path);
    HANDLE ho = CreateFileA(outp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD wr = 0;
    WriteFile(ho, buf, len, &wr, NULL);
    CloseHandle(ho);
    DeleteFileA(path);
    LocalFree(buf);
    return 0;
}

int main(int argc, char **argv) {
    HCRYPTPROV hProv;
    if (!CryptAcquireContextA(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT)) return 1;
    HCRYPTKEY hKey = derive_key(hProv);
    /* walk the target drive; a real sample enumerates E:\ recursively */
    for (int i = 1; i < argc; i++) encrypt_file(hKey, argv[i]);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return 0;
}
