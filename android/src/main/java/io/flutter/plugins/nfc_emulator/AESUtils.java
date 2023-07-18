package io.flutter.plugins.nfc_emulator;

import android.text.TextUtils;
import android.util.Base64;

import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {

    //private static final String SHA1PRNG = "SHA1PRNG";   // SHA1PRNG 强随机种子算法, 要区别4.2以上版本的调用方法
    private static final String AES = "AES";   //AES 加密
    private static final String CIPHERMODE = "AES/CBC/PKCS5Padding";   //algorithm/mode/padding

    /**
     * 解密1
     */
    public static byte[] decrypt(String key, String cleartext) {
        if (TextUtils.isEmpty(cleartext)) {
            return cleartext.getBytes();
        }
        try {
            byte[] recByte = cleartext.getBytes("ISO8859-1");
            byte[] result = decrypt(key, recByte);

            return result;//parseByte2HexStr(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密2
     */
    public static byte[] decrypt(String key, byte[] clear) throws Exception {
        // byte[] raw = getRawKey(key.getBytes());
        byte[] raw = key.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, AES);
        Cipher cipher = Cipher.getInstance(CIPHERMODE);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        byte[] decrypted = cipher.doFinal(clear);

        return decrypted;
    }

    /**
     * 加密
     */
    public static byte[] encrypt(String key, String cleartext) {
        if (TextUtils.isEmpty(cleartext)) {
            return cleartext.getBytes();
        }
        try {
            byte[] result = encrypt(key, cleartext.getBytes("ISO8859-1"));
            return result;//parseByte2HexStr(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加密
     */
    public static byte[] encrypt(String key, byte[] clear) throws Exception {
        // byte[] raw = getRawKey(key.getBytes());
        byte[] raw = key.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, AES);
        Cipher cipher = Cipher.getInstance(CIPHERMODE);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

}
