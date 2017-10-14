package ru.msu.cs.ib;

import java.security.MessageDigest;

public class JH extends MessageDigest {

    public static final int blockSizeInBytes = 64;
    public static final int hashSizeInBytes = 32;
    private char[] hash = new char[hashSizeInBytes * 4];
    private char[] message = new char[blockSizeInBytes];
    private int messageLength = 0;
    private int allMessageLength = 0;


    /**
     * Creates a message digest with the specified algorithm name.
     *
     * @param algorithm the standard name of the digest algorithm.
     *                  See the MessageDigest section in the <a href=
     *                  "{@docRoot}/../technotes/guides/security/StandardNames.html#MessageDigest">
     *                  Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     *                  for information about standard algorithm names.
     */
    public JH() {
        super("JH");
        engineReset();
    }

    private char[] padding(){
        int i, j, k;
        int n;
        char[] new_message;
        n = messageLength;
        int tmp = - n * 8;
        tmp %= 512;
        if (tmp < 0)
            tmp += 512;
        i = 383 + tmp;
        i = (1 + i) / 8;
        new_message = new char[n + i + 16];
        for (j = 0; j < n; j++)
            new_message[j] = message[j];
        new_message[j] = 0x80;
        for (k = j + 1; k < i + j; k++)
            new_message[k] = 0x00;
        n = allMessageLength * 8;
        for(j = 1; j <= 16; j++) {
            new_message[k + 16 - j] = (char) (n & 0xff);
            n /= 256;
        }
        return new_message;
    }

    private static final char S0 [] = {0x9,0x0,0x4,0xb,0xd,0xc,0x3,0xf,0x1,0xa,0x2,0x6,0x7,0x5,0x8,0xe};
    private static final char S1 [] = {0x3,0xc,0x6,0xd,0x5,0x7,0x1,0x9,0xf,0x2,0x0,0x4,0xb,0xa,0xe,0x8};

    private char[] R6(char[] A) {
        char[] tmp = new char[64];
        char t;
        int i;
        for(i = 0; i < 64; i++) {
            tmp[i] = S0[A[i]];
        }

        for(i = 0; i < 64; i += 2) {
            tmp[i + 1] ^= ((tmp[i] << 1) ^ (tmp[i] >> 3) ^ ((tmp[i] >> 2) & 2)) & 0xf;
            tmp[i] ^= ((tmp[i + 1] << 1) ^ (tmp[i + 1] >> 3) ^ ((tmp[i + 1] >> 2) & 2)) & 0xf;

        }

        for(i = 0; i < 16; i++) {
            t = tmp[4 * i + 2];
            tmp[4 * i + 2] = tmp[4 * i + 3];
            tmp[4 * i + 3] = t;
        }

        for(i = 0; i < 32; i++) {
            A[i] = tmp[2 * i];
            A[i + 32] = tmp[2 * i + 1];
        }

        for(i = 0; i < 16; i++) {
            tmp[2 * i] = A[2 * i];
            tmp[2 * i + 1] = A[2 * i + 1];
            tmp[2 * i + 32] = A[2 * i + 33];
            tmp[2 * i + 33] = A[2 * i + 32];
        }

        return tmp;
    }

    private char[] R8(char[] A, char[] C) {

        char[] tmp = new char[256];
        char t;
        int i;
        for(i = 0; i < 256; i++) {
            if ((C[i / 4] >> (3 - (i % 4)) & 1) == 0)
                tmp[i] = S0[A[i]];
            else
                tmp[i] = S1[A[i]];
        }

        for(i = 0; i < 256; i += 2) {
            tmp[i + 1] ^= ((tmp[i] << 1) ^ (tmp[i] >> 3) ^ ((tmp[i] >> 2) & 2)) & 0xf;
            tmp[i] ^= ((tmp[i + 1] << 1) ^ (tmp[i + 1] >> 3) ^ ((tmp[i + 1] >> 2) & 2)) & 0xf;
        }

        for(i = 0; i < 64; i++) {
            t = tmp[4 * i + 2];
            tmp[4 * i + 2] = tmp[4 * i + 3];
            tmp[4 * i + 3] = t;
        }

        for(i = 0; i < 128; i++) {
            A[i] = tmp[2 * i];
            A[i + 128] = tmp[2 * i + 1];
        }

        for(i = 0; i < 64; i++) {
            tmp[2 * i] = A[2 * i];
            tmp[2 * i + 1] = A[2 * i + 1];
            tmp[2 * i + 128] = A[2 * i + 129];
            tmp[2 * i + 129] = A[2 * i + 128];
        }
        return tmp;

    }

    private char[] E8 (char[] H) {
        char[] groups = new char[256];
        char t0, t1, t2, t3;
        int i;
        for(i = 0; i < 256; i++) {
            t0 = (char) ((H[i / 8] >> (7 - (i % 8))) & 1);
            t1 = (char)((H[(i + 256) / 8] >> (7 - (i % 8))) & 1);
            t2 = (char)((H[(i + 512) / 8] >> (7 - (i % 8))) & 1);
            t3 = (char)((H[(i + 768) / 8] >> (7 - (i % 8))) & 1);
            groups[i] = (char)((t0 << 3) | (t1 << 2) | (t2 << 1) | t3);
        }
        char[] regroups = new char[256];
        for(i = 0; i < 128; i++) {
            regroups[2 * i] = groups[i];
            regroups[2 * i + 1] = groups[i + 128];
        }

        char round_constants[] = {0x6,0xa,0x0,0x9,0xe,0x6,0x6,0x7,
                0xf,0x3,0xb,0xc,0xc,0x9,0x0,0x8,0xb,0x2,0xf,0xb,0x1,0x3,0x6,0x6,
                0xe,0xa,0x9,0x5,0x7,0xd,0x3,0xe,0x3,0xa,0xd,0xe,0xc,0x1,0x7,0x5,
                0x1,0x2,0x7,0x7,0x5,0x0,0x9,0x9,0xd,0xa,0x2,0xf,0x5,0x9,0x0,0xb,
                0x0,0x6,0x6,0x7,0x3,0x2,0x2,0xa};

        for(i = 0; i < 42; i++) {
            regroups = R8(regroups, round_constants);
            round_constants = R6(round_constants);
        }

        for(i = 0; i < 128; i++) {
            groups[i] = regroups[2 * i];
            groups[i + 128] = regroups[2 * i + 1];
            H[i] = 0;
        }
        for(i = 0; i < 256; i++) {
            t0 = (char)((groups[i] >> 3) & 1);
            t1 = (char)((groups[i] >> 2) & 1);
            t2 = (char)((groups[i] >> 1) & 1);
            t3 = (char)((groups[i]) & 1);
            H[i / 8] |= t0 << (7 - (i % 8));
            H[(i + 256) / 8] |= t1 << (7 - (i % 8));
            H[(i + 512) / 8] |= t2 << (7 - (i % 8));
            H[(i + 768) / 8] |= t3 << (7 - (i % 8));
        }
        return H;
    }

    private char[] F8 (char[] H) {
        int i;
        for(i = 0; i < 64; i++)
            H[i] ^= message[i];
        H = E8(H);
        for(i = 0; i < 64; i++)
            H[i + 64] ^= message[i];
        return H;
    }

    @Override
    public void engineUpdate(byte input) {
        int i;
        message[messageLength] = (char) (input & 0xff);
        messageLength++;
        allMessageLength++;
        if (messageLength == blockSizeInBytes) {
            hash = F8(hash);
            for(i = 0; i < blockSizeInBytes; i++) {
                message[i] = 0;
            }
            messageLength = 0;
        }
    }

    @Override
    public void engineUpdate(byte[] input, int offset, int len) {
        int i;
        for(i = 0; i < len; i++) {
            engineUpdate(input[offset + i]);
        }
    }

    @Override
    public byte[] engineDigest() {
        char[] new_message = padding();
        messageLength = new_message.length; //64(если длина сообщения кратна 64) или 128 (иначе)
        int i;
        if (messageLength != 64) {
            for(i = 0; i < 64; i++)
                message[i] = new_message[i];
            hash = F8(hash);
            for(i = 0; i < 64; i++)
                message[i] = new_message[i + 64];
            hash = F8(hash);
        } else
            hash = F8(hash);
        byte[] result = new byte[32];
        for(i = 0; i < hashSizeInBytes; i++)
            result[i] = (byte) (hash[96 + i] & 0xff);
        engineReset();
        return result;
    }

    @Override
    public void engineReset() {
        int i;
        for(i = 0; i < blockSizeInBytes; i++) {
            message[i] = 0;
        }
        messageLength = 0;
        allMessageLength = 0;
        hash[0] = 0x01;
        hash[1] = 0x00;
        for(i = 2; i < hashSizeInBytes * 4; i++)
            hash[i] = 0;
        hash = F8(hash);
    }
}
