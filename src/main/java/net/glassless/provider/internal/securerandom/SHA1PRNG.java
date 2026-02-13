package net.glassless.provider.internal.securerandom;

/**
 * SHA1PRNG SecureRandom implementation.
 * For compatibility, this uses OpenSSL's random number generator
 * rather than implementing a pure Java SHA-1 based PRNG.
 * OpenSSL's RNG is cryptographically stronger than SHA1PRNG.
 */
public class SHA1PRNG extends OpenSSLSecureRandom {

    private static final long serialVersionUID = 1L;

    public SHA1PRNG() {
        super();
    }
}
