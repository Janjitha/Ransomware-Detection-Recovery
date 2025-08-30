package com.insurai.ransomguard;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    private static final String ALGO = "AES";
    public static final String KEY = "1234567890123456"; // 16-byte key (for demo only!)

    public static byte[] encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(ALGO);
        SecretKeySpec k = new SecretKeySpec(KEY.getBytes(), ALGO);
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher c = Cipher.getInstance(ALGO);
        SecretKeySpec k = new SecretKeySpec(KEY.getBytes(), ALGO);
        c.init(Cipher.DECRYPT_MODE, k);
        return c.doFinal(encryptedData);
    }
}
