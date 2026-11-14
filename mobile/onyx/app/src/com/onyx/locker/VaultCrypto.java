package com.onyx.locker;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// local vault-at-rest encryption. the key and IV are compiled into the app.
public class VaultCrypto {
    private static final byte[] KEY = "0nyxL0ck3r_v4ult_K3y_32bytes_ok!".getBytes();
    private static final byte[] IV = "0nyxLckrIV_16byt".getBytes();

    public static byte[] encrypt(byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
        return c.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
        return c.doFinal(ciphertext);
    }
}
