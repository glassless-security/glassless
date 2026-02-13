package net.glassless.provider.internal.securerandom;

/**
 * DRBG (Deterministic Random Bit Generator) SecureRandom implementation.
 * This uses OpenSSL's random number generator which internally uses
 * a DRBG seeded from system entropy sources.
 */
public class DRBG extends OpenSSLSecureRandom {

    private static final long serialVersionUID = 1L;

    public DRBG() {
        super();
    }
}
