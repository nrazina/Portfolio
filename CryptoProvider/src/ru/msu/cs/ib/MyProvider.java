package ru.msu.cs.ib;

import java.security.*;

public final class MyProvider extends Provider {

    private static final String info = "MyProvider " +
            "Whirlpool, JH256 digests";

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name    the provider name.
     * @param version the provider version number.
     * @param info    a description of the provider and its services.
     */
    public MyProvider() {
        super("MyProvider", 1.0, info);
        AccessController.doPrivileged(new java.security.PrivilegedAction() {
            public Object run() {

                put("MessageDigest.Whirlpool", "ru.msu.cs.ib.Whirlpool");
                put("MessageDigest.JH", "ru.msu.cs.ib.JH");

                return null;
            }
        });
    }
}
