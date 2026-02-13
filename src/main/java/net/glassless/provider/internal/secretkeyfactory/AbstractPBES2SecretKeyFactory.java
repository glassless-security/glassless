package net.glassless.provider.internal.secretkeyfactory;

import java.lang.foreign.Arena;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract SecretKeyFactory for PBES2 (Password-Based Encryption Scheme 2).
 * Combines PBKDF2 key derivation with a symmetric cipher (e.g., AES).
 */
public abstract class AbstractPBES2SecretKeyFactory extends SecretKeyFactorySpi {

    private final String algorithm;
    private final String digestName;
    private final int keyLengthBits;

    /**
     * Create a PBES2 SecretKeyFactory.
     *
     * @param algorithm the algorithm name (e.g., "PBEWithHmacSHA256AndAES_128")
     * @param digestName the HMAC digest name (e.g., "SHA256")
     * @param keyLengthBits the cipher key length in bits (e.g., 128 or 256)
     */
    protected AbstractPBES2SecretKeyFactory(String algorithm, String digestName, int keyLengthBits) {
        this.algorithm = algorithm;
        this.digestName = digestName;
        this.keyLengthBits = keyLengthBits;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec pbeKeySpec)) {
            throw new InvalidKeySpecException("KeySpec must be a PBEKeySpec");
        }

        char[] password = pbeKeySpec.getPassword();
        if (password == null) {
            throw new InvalidKeySpecException("Password cannot be null");
        }

        byte[] salt = pbeKeySpec.getSalt();
        if (salt == null) {
            throw new InvalidKeySpecException("Salt cannot be null");
        }

        int iterationCount = pbeKeySpec.getIterationCount();
        if (iterationCount <= 0) {
            throw new InvalidKeySpecException("Iteration count must be positive");
        }

        // For PBES2, the key length is determined by the cipher, not the key spec
        // The keySpec keyLength is ignored - we use the cipher's required key size
        int keyLength = keyLengthBits;

        try (Arena arena = Arena.ofConfined()) {
            // Convert password to UTF-8 bytes
            byte[] passwordBytes = new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);

            try {
                // Derive the key using PBKDF2
                byte[] derivedKey = OpenSSLCrypto.PKCS5_PBKDF2_HMAC(
                    passwordBytes,
                    salt,
                    iterationCount,
                    digestName,
                    keyLength / 8,
                    arena
                );

                // Return the key with the PBE algorithm name
                return new PBES2SecretKey(derivedKey, algorithm);
            } finally {
                // Clear sensitive data
                java.util.Arrays.fill(passwordBytes, (byte) 0);
            }

        } catch (Throwable e) {
            throw new ProviderException("Error deriving key with PBES2", e);
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        // We cannot return a PBEKeySpec since we don't have the original password
        throw new InvalidKeySpecException("Cannot extract PBEKeySpec from derived key");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        // If already the correct type, return as-is
        if (key.getAlgorithm().equals(algorithm)) {
            return key;
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }

        return new PBES2SecretKey(encoded, algorithm);
    }

    /**
     * Internal PBES2 SecretKey implementation.
     */
    private static class PBES2SecretKey implements SecretKey {
        private static final long serialVersionUID = 1L;

        private final byte[] keyBytes;
        private final String algorithm;

        PBES2SecretKey(byte[] keyBytes, String algorithm) {
            this.keyBytes = keyBytes.clone();
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return keyBytes.clone();
        }

        @Override
        public void destroy() {
            java.util.Arrays.fill(keyBytes, (byte) 0);
        }

        @Override
        public boolean isDestroyed() {
            for (byte b : keyBytes) {
                if (b != 0) return false;
            }
            return true;
        }
    }
}
