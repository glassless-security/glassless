package net.glassless.provider.internal.securerandom;

import java.security.SecureRandomSpi;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * SecureRandom implementation using OpenSSL's RAND_bytes.
 * This provides cryptographically secure random number generation
 * using OpenSSL's default random number generator (typically based on
 * system entropy sources like /dev/urandom).
 */
public class OpenSSLSecureRandom extends SecureRandomSpi {

    private static final long serialVersionUID = 1L;

    public OpenSSLSecureRandom() {
        // OpenSSL's RNG is self-seeding from system entropy
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        if (seed == null || seed.length == 0) {
            return;
        }
        try {
            OpenSSLCrypto.RAND_seed(seed);
        } catch (Throwable e) {
            // Seeding is optional, ignore errors
        }
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return;
        }
        try {
            byte[] random = OpenSSLCrypto.RAND_bytes(bytes.length);
            System.arraycopy(random, 0, bytes, 0, bytes.length);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to generate random bytes", e);
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes <= 0) {
            return new byte[0];
        }
        try {
            return OpenSSLCrypto.RAND_bytes(numBytes);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to generate seed bytes", e);
        }
    }
}
