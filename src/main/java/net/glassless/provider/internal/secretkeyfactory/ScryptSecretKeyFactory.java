package net.glassless.provider.internal.secretkeyfactory;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * SecretKeyFactory for SCRYPT key derivation using OpenSSL.
 *
 * SCRYPT is a password-based key derivation function designed to be
 * computationally intensive and memory-hard, making it resistant to
 * hardware brute-force attacks.
 */
public class ScryptSecretKeyFactory extends SecretKeyFactorySpi {

    private static final String ALGORITHM = "SCRYPT";

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof ScryptKeySpec)) {
            throw new InvalidKeySpecException("KeySpec must be a ScryptKeySpec");
        }

        ScryptKeySpec scryptSpec = (ScryptKeySpec) keySpec;

        char[] password = scryptSpec.getPassword();
        byte[] salt = scryptSpec.getSalt();
        int n = scryptSpec.getCostParameter();
        int r = scryptSpec.getBlockSize();
        int p = scryptSpec.getParallelization();
        int keyLengthBits = scryptSpec.getKeyLength();
        int keyLengthBytes = keyLengthBits / 8;

        // Convert password to bytes (UTF-8)
        byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);

        try {
            // Fetch the SCRYPT KDF
            int kdf = OpenSSLCrypto.EVP_KDF_fetch(0, "SCRYPT", 0);
            if (kdf == 0) {
                throw new ProviderException("Failed to fetch SCRYPT KDF");
            }

            try {
                // Create KDF context
                int ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
                if (ctx == 0) {
                    throw new ProviderException("Failed to create SCRYPT context");
                }

                try {
                    // Create SCRYPT parameters
                    int osslParams = OpenSSLCrypto.createScryptParams(
                        passwordBytes, salt, n, r, p
                    );

                    // Allocate output buffer
                    int output = OpenSSLCrypto.malloc(keyLengthBytes);

                    try {
                        // Derive the key
                        int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, keyLengthBytes, osslParams);
                        if (result != 1) {
                            throw new ProviderException("SCRYPT key derivation failed");
                        }

                        // Extract the derived key
                        byte[] derivedKey = OpenSSLCrypto.memory().readBytes(output, keyLengthBytes);

                        return new SecretKeySpec(derivedKey, ALGORITHM);
                    } finally {
                        OpenSSLCrypto.free(output);
                        OpenSSLCrypto.free(osslParams);
                    }
                } finally {
                    OpenSSLCrypto.EVP_KDF_CTX_free(ctx);
                }
            } finally {
                OpenSSLCrypto.EVP_KDF_free(kdf);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error deriving key with SCRYPT", e);
        } finally {
            // Clear sensitive data
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }
        // Cannot extract ScryptKeySpec from derived key (no password info)
        throw new InvalidKeySpecException("Cannot extract ScryptKeySpec from derived key");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key.getAlgorithm().equals(ALGORITHM)) {
            return key;
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }

        return new SecretKeySpec(encoded, ALGORITHM);
    }
}
