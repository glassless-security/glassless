package net.glassless.provider.internal.secretkeyfactory;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;

/**
 * SecretKeyFactory for PBE (Password-Based Encryption).
 * Creates a PBEKey from a PBEKeySpec containing a password.
 */
public class PBESecretKeyFactory extends SecretKeyFactorySpi {

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

        return new PBESecretKey(password);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (!(key instanceof PBESecretKey)) {
            throw new InvalidKeySpecException("Key must be a PBE key");
        }

        if (keySpecClass == null || !PBEKeySpec.class.isAssignableFrom(keySpecClass)) {
            throw new InvalidKeySpecException("Only PBEKeySpec is supported");
        }

        PBESecretKey pbeKey = (PBESecretKey) key;
        return new PBEKeySpec(pbeKey.getPassword());
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key instanceof PBESecretKey) {
            return key;
        }

        // Cannot translate non-PBE keys
        throw new InvalidKeyException("Cannot translate key to PBE key");
    }

    /**
     * Internal PBE SecretKey implementation that holds the password.
     */
    private static class PBESecretKey implements SecretKey {
        private static final long serialVersionUID = 1L;

        private final char[] password;

        PBESecretKey(char[] password) {
            this.password = password.clone();
        }

        char[] getPassword() {
            return password.clone();
        }

        @Override
        public String getAlgorithm() {
            return "PBE";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            // Convert password to UTF-8 bytes
            return new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

        @Override
        public void destroy() {
            java.util.Arrays.fill(password, '\0');
        }

        @Override
        public boolean isDestroyed() {
            for (char c : password) {
                if (c != '\0') return false;
            }
            return true;
        }
    }
}
