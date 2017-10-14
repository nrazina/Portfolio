package ru.msu.cs.ib;

import java.security.*;
import org.junit.Test;

public class Testing {

    public static void testEquals(byte[] res, byte[] real)
    {
        org.junit.Assert.assertEquals(res.length, real.length);
        int i;
        for(i = 0; i < res.length; i++)
            org.junit.Assert.assertEquals(res[i], real[i]);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

        String str = "The quick brown fox jumps over the lazy dog";
        int t = str.length();
        byte[] m = new byte[str.length()];
        int i;
        for(i = 0; i < str.length(); i++)
            m[i] = (byte) (str.charAt(i));
        MessageDigest digest;
        digest = MessageDigest.getInstance("Whirlpool", "MyProvider");
        digest.update(m, 0, str.length());
        byte[] res = digest.digest();
        byte[] realWhirlpool = {(byte)0xb9, 0x7d, (byte)0xe5, 0x12, (byte)0xe9, 0x1e, 0x38, 0x28, (byte)0xb4,
                0x0d, 0x2b, 0x0f, (byte)0xdc, (byte)0xe9, (byte)0xce, (byte)0xb3, (byte)0xc4, (byte)0xa7, 0x1f,
                (byte)0x9b, (byte)0xea, (byte)0x8d, (byte)0x88, (byte)0xE7, 0x5C, 0x4F, (byte)0xA8, 0x54,
                (byte)0xDF, 0x36, 0x72, 0x5F, (byte)0xD2, (byte)0xB5, 0x2E, (byte)0xB6, 0x54, 0x4E, (byte)0xDC,
                (byte)0xAC, (byte)0xD6, (byte)0xF8, (byte)0xBE, (byte)0xDD, (byte)0xFE, (byte)0xA4, 0x03,
                (byte)0xCB, 0x55, (byte)0xAE, 0x31, (byte)0xF0, 0x3A, (byte)0xD6, 0x2A,
                0x5E, (byte)0xF5, 0x4E, 0x42, (byte)0xEE, (byte)0x82, (byte)0xC3, (byte)0xFB, 0x35};
        testEquals(res, realWhirlpool);

        digest = MessageDigest.getInstance("JH", "MyProvider");
        digest.update(m, 0, str.length());
        res = digest.digest();
        byte[] realJH = {0x6a, 0x04, (byte)0x9f, (byte)0xed, 0x5f, (byte)0xc6, (byte)0x87, 0x4a,
                (byte)0xcf, (byte)0xdc, 0x4a, 0x08, (byte)0xb5, 0x68, (byte)0xa4, (byte)0xf8, (byte)0xcb, (byte)0xac,
                0x27, (byte)0xde, (byte)0x93, 0x34, (byte)0x96, (byte)0xf0, 0x31, 0x01, 0x5b,
                0x38, (byte)0x96, 0x16, 0x08, (byte)0xa0};
        testEquals(res, realJH);

    }
}
