package net.glassless.provider.internal.secretkeyfactory;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SecretKeyFactory for DESede (Triple DES) keys.
 */
public class DESedeSecretKeyFactory extends SecretKeyFactorySpi {

    private static final String ALGORITHM = "DESede";
    private static final int KEY_LENGTH = 24; // 192 bits

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof DESedeKeySpec) {
            DESedeKeySpec desedeKeySpec = (DESedeKeySpec) keySpec;
            byte[] keyBytes = desedeKeySpec.getKey();

            // Ensure proper key length
            if (keyBytes.length < KEY_LENGTH) {
                throw new InvalidKeySpecException("DESede key must be at least 24 bytes");
            }

            // Use first 24 bytes
            byte[] key = new byte[KEY_LENGTH];
            System.arraycopy(keyBytes, 0, key, 0, KEY_LENGTH);

            // Set parity bits
            setParityBits(key);

            return new SecretKeySpec(key, ALGORITHM);

        } else if (keySpec instanceof SecretKeySpec) {
            SecretKeySpec secretKeySpec = (SecretKeySpec) keySpec;
            if (!secretKeySpec.getAlgorithm().equals(ALGORITHM) &&
                !secretKeySpec.getAlgorithm().equals("TripleDES")) {
                throw new InvalidKeySpecException("Key algorithm must be DESede or TripleDES");
            }
            return new SecretKeySpec(secretKeySpec.getEncoded(), ALGORITHM);

        } else {
            throw new InvalidKeySpecException("KeySpec must be DESedeKeySpec or SecretKeySpec");
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

        if (DESedeKeySpec.class.isAssignableFrom(keySpecClass)) {
            try {
                return new DESedeKeySpec(encoded);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException("Cannot create DESedeKeySpec", e);
            }
        } else if (SecretKeySpec.class.isAssignableFrom(keySpecClass)) {
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

        if (key.getAlgorithm().equals(ALGORITHM) || key.getAlgorithm().equals("TripleDES")) {
            if (key instanceof SecretKeySpec) {
                return key;
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            return new SecretKeySpec(encoded, ALGORITHM);
        }

        throw new InvalidKeyException("Cannot translate key with algorithm: " + key.getAlgorithm());
    }

    /**
     * Sets the parity bit (LSB) of each byte to make odd parity.
     */
    private void setParityBits(byte[] key) {
        for (int i = 0; i < key.length; i++) {
            int b = key[i] & 0xFE;
            int count = Integer.bitCount(b);
            key[i] = (byte) (b | ((count % 2 == 0) ? 1 : 0));
        }
    }
}
