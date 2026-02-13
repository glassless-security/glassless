package net.glassless.provider.internal.secretkeyfactory;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

/**
 * SecretKeyFactory for AES keys.
 */
public class AESSecretKeyFactory extends SecretKeyFactorySpi {

    private static final String ALGORITHM = "AES";

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof SecretKeySpec) {
            SecretKeySpec secretKeySpec = (SecretKeySpec) keySpec;
            String algorithm = secretKeySpec.getAlgorithm();

            if (!algorithm.equals(ALGORITHM) && !algorithm.startsWith("AES")) {
                throw new InvalidKeySpecException("Key algorithm must be AES");
            }

            byte[] encoded = secretKeySpec.getEncoded();
            validateKeyLength(encoded.length);

            return new SecretKeySpec(encoded, ALGORITHM);

        } else {
            throw new InvalidKeySpecException("KeySpec must be SecretKeySpec for AES");
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeySpecException("Key does not support encoding");
        }

        if (keySpecClass == null) {
            throw new InvalidKeySpecException("KeySpec class cannot be null");
        }

        if (SecretKeySpec.class.isAssignableFrom(keySpecClass)) {
            return new SecretKeySpec(encoded, ALGORITHM);
        } else {
            throw new InvalidKeySpecException("Unsupported KeySpec class: " + keySpecClass.getName());
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        String algorithm = key.getAlgorithm();
        if (algorithm.equals(ALGORITHM) || algorithm.startsWith("AES")) {
            if (key instanceof SecretKeySpec) {
                return key;
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            validateKeyLengthForTranslate(encoded.length);
            return new SecretKeySpec(encoded, ALGORITHM);
        }

        throw new InvalidKeyException("Cannot translate key with algorithm: " + algorithm);
    }

    private void validateKeyLength(int length) throws InvalidKeySpecException {
        if (length != 16 && length != 24 && length != 32) {
            throw new InvalidKeySpecException("AES key must be 128, 192, or 256 bits (16, 24, or 32 bytes)");
        }
    }

    private void validateKeyLengthForTranslate(int length) throws InvalidKeyException {
        if (length != 16 && length != 24 && length != 32) {
            throw new InvalidKeyException("AES key must be 128, 192, or 256 bits (16, 24, or 32 bytes)");
        }
    }
}
