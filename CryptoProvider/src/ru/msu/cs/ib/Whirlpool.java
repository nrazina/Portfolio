package ru.msu.cs.ib;

import java.security.MessageDigest;

public class Whirlpool extends MessageDigest {


    public static final int digestSizeInBytes = 64;
    private char[] hash = new char[digestSizeInBytes];
    private char[] message = new char[digestSizeInBytes];
    private int messageLength = 0;

    public static final char sbox[] = {
            0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
            0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
            0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
            0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
            0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
            0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
            0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
            0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
            0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
            0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
            0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
            0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
            0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
            0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
            0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
            0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
    };

    public static final int R = 10;
    private char cr[][] = new char[8][8];

    public static final char C[][] = {
            {0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09},
            {0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02},
            {0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05},
            {0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08},
            {0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01},
            {0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04},
            {0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01},
            {0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01}
    };


    private char roundKeys[][] = new char[R + 1][digestSizeInBytes];

    /**
     * Creates a message digest with the specified algorithm name.
     *
     * @param algorithm the standard name of the digest algorithm.
     *                  See the MessageDigest section in the <a href=
     *                  "{@docRoot}/../technotes/guides/security/StandardNames.html#MessageDigest">
     *                  Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     *                  for information about standard algorithm names.
     */
    public Whirlpool() {
        super("Whirlpool");
        engineReset();
    }

    private char multiply(char pi, char c) {
        char result = 0;
        char[] number = new char[15];
        int i, j, k, t;
        for(i = 0; i < 15; i++)
            number[i] = 0;
        k = 7;
        for(i = 128; i > 0; i/= 2, k--) {
            t = 7;
            for(j = 128; j > 0; j/= 2, t--)
                if (((pi % (i * 2)) / i == 1) && ((c % (j * 2)) / j == 1))
                    number[k + t] ^= 1;
        }
        if (number[14] == 1) {
            number[4] ^= 1;
            number[1] ^= 1;
            number[0] ^= 1;
        }
        if (number[13] == 1) {
            number[7] ^= 1;
            number[2] ^= 1;
            number[1] ^= 1;
            number[0] ^= 1;
        }
        if (number[12] == 1) {
            number[7] ^= 1;
            number[6] ^= 1;
            number[3] ^= 1;
            number[2] ^= 1;
            number[0] ^= 1;
        }
        if (number[11] == 1) {
            number[7] ^= 1;
            number[6] ^= 1;
            number[5] ^= 1;
            number[3] ^= 1;
        }
        if (number[10] == 1) {
            number[6] ^= 1;
            number[5] ^= 1;
            number[4] ^= 1;
            number[2] ^= 1;
        }
        if (number[9] == 1) {
            number[5] ^= 1;
            number[4] ^= 1;
            number[3] ^= 1;
            number[1] ^= 1;
        }
        if (number[8] == 1) {
            number[4] ^= 1;
            number[3] ^= 1;
            number[2] ^= 1;
            number[0] ^= 1;
        }
        for(i = 7; i >= 0; i--) {
            result *= 2;
            result += number[i];
        }
        return result;
    }

    private void CreateRoundKeys(char key[]){

        int i, j, r, k, tmp;
        char [][] gamma = new char[R + 1][digestSizeInBytes];
        char [][] pi = new char[R + 1][digestSizeInBytes];
        char [][] theta = new char[R + 1][digestSizeInBytes];
        for(i = 0; i < digestSizeInBytes; i++)
            roundKeys[0][i] = key[i];
        for(r = 1; r <= R; r++) {

            for (j = 0; j < 8; j++)
                cr[0][j] = sbox[8 * (r - 1) + j];
            for(i = 1; i < 8; i++)
                for(j = 0; j < 8; j++)
                    cr[i][j] = 0;

            for(i = 0; i < digestSizeInBytes; i++)
                gamma[r][i] = sbox[roundKeys[r - 1][i]];
            for(i = 0; i < digestSizeInBytes; i++) {
                tmp = ((i / 8) - (i % 8)) % 8;
                if (tmp < 0)
                    tmp += 8;
                pi[r][i] = gamma[r][8 * tmp + (i % 8)];
            }
            for(i = 0; i < digestSizeInBytes; i++)
                theta[r][i] = 0;
            for(i = 0; i < 8; i++)
                for(j = 0; j < 8; j++)
                    for(k = 0; k < 8; k++)
                        theta[r][i * 8 + j] ^= multiply(pi[r][i * 8 + k], C[k][j]);
            for(i = 0; i < digestSizeInBytes; i++) {
                roundKeys[r][i] = (char) (theta[r][i] ^ cr[i / 8][i % 8]);
                roundKeys[r][i] &= 0xFF;
            }

        }

    }

    private char[] encoding(char[] key){
        CreateRoundKeys(key);
        char [][] gamma = new char[R + 1][digestSizeInBytes];
        char [][] pi = new char[R + 1][digestSizeInBytes];
        char [][] theta = new char[R + 1][digestSizeInBytes];
        char sigma[] = new char[digestSizeInBytes];
        int i, r, j, k, tmp;
        for(i = 0; i < digestSizeInBytes; i++) {
            sigma[i] = (char) (roundKeys[0][i] ^ message[i]);
            sigma[i] &= 0xFF;
        }
        for(r = 1; r <= R; r++) {

            for(i = 0; i < digestSizeInBytes; i++)
                gamma[r][i] = sbox[sigma[i]];
            for(i = 0; i < digestSizeInBytes; i++) {
                tmp = ((i / 8) - (i % 8)) % 8;
                if (tmp < 0)
                    tmp += 8;
                pi[r][i] = gamma[r][8 * tmp + (i % 8)];
            }
            for(i = 0; i < digestSizeInBytes; i++)
                theta[r][i] = 0;
            for(i = 0; i < 8; i++)
                for(j = 0; j < 8; j++)
                    for(k = 0; k < 8; k++)
                        theta[r][i * 8 + j] ^= multiply(pi[r][i * 8 + k], C[k][j]);
            for(i = 0; i < digestSizeInBytes; i++) {
                sigma[i] = (char) (theta[r][i] ^ roundKeys[r][i]);
                sigma[i] &= 0xFF;
            }
        }
        return sigma;
    }

    private char[] padding(){
        int i, j, k;
        int n;
        char[] new_message;
        n = messageLength;
        i = 256 - (n * 8 + 1) % 256;
        if (((n * 8 + 1 + i) / 256) % 2 == 0)
            i += 256;
        i = (1 + i) / 8;
        new_message = new char[n + i + 32];
        for (j = 0; j < n; j++)
            new_message[j] = message[j];
        new_message[j] = 0x80;
        for (k = j + 1; k < i + j; k++)
            new_message[k] = 0x00;
        n *= 8;
        for(j = 1; j <= 32; j++) {
            new_message[k + 32 - j] = (char) ((n % 256) & 0xFF);
            n /= 256;
        }
        n = new_message.length;
        char[] new_hash;
        for(i = 0; i < n / digestSizeInBytes; i++) {
            for(j = 0; j < digestSizeInBytes; j++)
                message[j] = new_message[i * digestSizeInBytes + j];
            new_hash = encoding(hash);
            for(j = 0; j < digestSizeInBytes; j++) {
                hash[j] ^= new_hash[j];
                hash[j] ^= message[j];
            }
        }
        return hash;
    }

    @Override
    public void engineUpdate(byte input) {
        message[messageLength] = (char) (input & 0xff);
        messageLength++;
        if (messageLength == digestSizeInBytes) {
            char new_hash[];
            new_hash = encoding(hash);
            int j;
            for(j = 0; j < digestSizeInBytes; j++) {
                hash[j] ^= new_hash[j];
                hash[j] ^= message[j];
            }
            for(int i = 0; i < digestSizeInBytes; i++) {
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
        int j;
        if (messageLength != 0) {
            char new_hash[];
            new_hash = padding();
            byte result[] = new byte[digestSizeInBytes];
            for (j = 0; j < digestSizeInBytes; j++)
                result[j] = (byte) (new_hash[j] & 0xff);
            engineReset();
            return result;
        }
        byte result[] = new byte[digestSizeInBytes];
        for (j = 0; j < digestSizeInBytes; j++)
            result[j] = (byte) (hash[j] & 0xff);
        engineReset();
        return result;
    }

    @Override
    public void engineReset() {
        int i;
        for(i = 0; i < digestSizeInBytes; i++) {
            hash[i] = 0;
            message[i] = 0;
        }
        messageLength = 0;
    }

}
