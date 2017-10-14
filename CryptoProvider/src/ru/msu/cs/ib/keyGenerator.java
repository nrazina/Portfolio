package ru.msu.cs.ib;

import java.security.SecureRandom;

public class keyGenerator {

    public static byte[] generate_key(int n) {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[n];
        random.nextBytes(bytes);
        return bytes;
    }

}
