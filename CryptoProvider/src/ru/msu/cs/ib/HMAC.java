package ru.msu.cs.ib;

import java.security.*;
import java.util.ArrayList;

public class HMAC {

    public static final int blockSizeInBytes = 64;
    public static final int hashSizeInBytes = 32;
    private static byte[] ipad = new byte[blockSizeInBytes];
    private static byte[] opad = new byte[blockSizeInBytes];
    private static byte[] Si = new byte[blockSizeInBytes];
    private static byte[] So = new byte[blockSizeInBytes];
    private static int messageLength = 0;
    static ArrayList<Byte> message = new ArrayList<Byte>();

    public static int GetMacLength() {
        return hashSizeInBytes;
    }

    public static void Init(byte[] key) throws NoSuchProviderException, NoSuchAlgorithmException {
        int i;
        for(i = 0; i < blockSizeInBytes; i++) {
            ipad[i] = 0x36;
            opad[i] = 0x5c;
        }
        byte[] new_key = new byte[blockSizeInBytes];
        if (key.length == blockSizeInBytes) {
            for(i = 0; i < key.length; i++)
                new_key[i] = key[i];
        } else if (key.length > blockSizeInBytes) {
            MessageDigest JH = MessageDigest.getInstance("JH", "MyProvider");
            JH.update(key, 0, key.length);
            new_key = JH.digest();
            for(i = hashSizeInBytes; i < blockSizeInBytes; i++)
                new_key[i] = 0x0;
        } else {
            for(i = 0; i < key.length; i++)
                new_key[i] = key[i];
            for(i = key.length; i < blockSizeInBytes; i++)
                new_key[i] = 0x0;
        }
        for(i = 0; i < blockSizeInBytes; i++) {
            Si[i] = (byte)(new_key[i] ^ ipad[i]);
            So[i] = (byte)(new_key[i] ^ opad[i]);
        }
        for (i = 0; i < blockSizeInBytes; i++)
        {
            message.add(Si[i]);
        }
    }

    public static void Update(byte b) {
        int i;
        if (messageLength == blockSizeInBytes) {
            messageLength = 0;
            for (i = 0; i < blockSizeInBytes; i++)
            {
                message.add(Si[i]);
            }
        }
        message.add(b);
        messageLength++;
    }

    public static void Update(byte[] bytes, int i, int i1) {
        int j;
        for(j = 0; j < i1; j++)
            Update(bytes[i + j]);
    }

    public static byte[] DoFinal() throws NoSuchProviderException, NoSuchAlgorithmException {
        int i;
        byte[] result = new byte[message.size()];
        for(i = 0; i < message.size(); i++)
            result[i] = (byte)(message.toArray()[i]);
        MessageDigest JH = MessageDigest.getInstance("JH", "MyProvider");
        JH.update(result, 0, message.size());
        result = JH.digest();
        byte[] new_text = new byte[blockSizeInBytes + hashSizeInBytes];
        for (i = 0; i < blockSizeInBytes; i++)
            new_text[i] = So[i];
        for (i = 0; i < hashSizeInBytes; i++)
            new_text[i + blockSizeInBytes] = result[i];
        JH.update(new_text, 0, blockSizeInBytes + hashSizeInBytes);
        result = JH.digest();
        Reset();
        return result;
    }

    public static void Reset() {
        int i;
        for(i = 0; i < blockSizeInBytes; i++) {
            Si[i] = 0;
            So[i] = 0;
        }
        messageLength = 0;
        message.clear();
    }
}
