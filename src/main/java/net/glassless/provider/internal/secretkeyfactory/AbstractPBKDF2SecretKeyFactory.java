package net.glassless.provider.internal.secretkeyfactory;

import java.lang.foreign.Arena;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract SecretKeyFactory for PBKDF2 key derivation using OpenSSL.
 */
public abstract class AbstractPBKDF2SecretKeyFactory extends SecretKeyFactorySpi {

    /**
     * Password encoding scheme for PBKDF2.
     */
    public enum PasswordEncoding {
        /** UTF-8 encoding (default) */
        UTF8,
        /** 8-bit encoding - lower 8 bits of each char */
        EIGHT_BIT
    }

    private final String algorithm;
    private final String digestName;
    private final int defaultKeyLength; // in bits
    private final PasswordEncoding encoding;

    protected AbstractPBKDF2SecretKeyFactory(String algorithm, String digestName, int defaultKeyLength) {
        this(algorithm, digestName, defaultKeyLength, PasswordEncoding.UTF8);
    }

    protected AbstractPBKDF2SecretKeyFactory(String algorithm, String digestName, int defaultKeyLength, PasswordEncoding encoding) {
        this.algorithm = algorithm;
        this.digestName = digestName;
        this.defaultKeyLength = defaultKeyLength;
        this.encoding = encoding;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new InvalidKeySpecException("KeySpec must be a PBEKeySpec");
        }

        PBEKeySpec pbeKeySpec = (PBEKeySpec) keySpec;

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

        int keyLength = pbeKeySpec.getKeyLength();
        if (keyLength <= 0) {
            keyLength = defaultKeyLength;
        }

        try (Arena arena = Arena.ofConfined()) {
            // Convert password to bytes based on encoding scheme
            byte[] passwordBytes = encodePassword(password);

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

                return new SecretKeySpec(derivedKey, algorithm);
            } finally {
                // Clear sensitive data
                java.util.Arrays.fill(passwordBytes, (byte) 0);
            }

        } catch (Throwable e) {
            throw new ProviderException("Error deriving key with PBKDF2", e);
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (keySpecClass == null || !keySpecClass.isAssignableFrom(SecretKeySpec.class)) {
            throw new InvalidKeySpecException("Unsupported key spec class: " + keySpecClass);
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeySpecException("Key does not support encoding");
        }

        // Return the raw key material wrapped in appropriate spec
        // Note: We cannot return a PBEKeySpec since we don't have the original password
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

        return new SecretKeySpec(encoded, algorithm);
    }

    /**
     * Encode the password according to the configured encoding scheme.
     */
    private byte[] encodePassword(char[] password) {
        if (encoding == PasswordEncoding.EIGHT_BIT) {
            // 8-bit encoding: take lower 8 bits of each char
            byte[] result = new byte[password.length];
            for (int i = 0; i < password.length; i++) {
                result[i] = (byte) (password[i] & 0xFF);
            }
            return result;
        } else {
            // UTF-8 encoding (default)
            return new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}
