package net.glassless.provider.internal.keypairgen;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * RSA KeyPairGenerator using OpenSSL.
 */
public class RSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int DEFAULT_KEY_SIZE = 2048;
    private static final int MIN_KEY_SIZE = 512;
    private static final int MAX_KEY_SIZE = 16384;

    private int keySize = DEFAULT_KEY_SIZE;
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize < MIN_KEY_SIZE || keysize > MAX_KEY_SIZE) {
            throw new InvalidParameterException("Key size must be between " + MIN_KEY_SIZE + " and " + MAX_KEY_SIZE + " bits");
        }
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof RSAKeyGenParameterSpec rsaParams) {
           int keysize = rsaParams.getKeysize();
            if (keysize < MIN_KEY_SIZE || keysize > MAX_KEY_SIZE) {
                throw new InvalidAlgorithmParameterException("Key size must be between " + MIN_KEY_SIZE + " and " + MAX_KEY_SIZE + " bits");
            }
            this.keySize = keysize;
            this.random = random;
        } else if (params != null) {
            throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // Create RSA key generation context
            int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(0, "RSA", 0);
            if (ctx == 0) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for RSA");
            }

            try {
                // Initialize for key generation
                int result = OpenSSLCrypto.EVP_PKEY_keygen_init(ctx);
                if (result <= 0) {
                    throw new ProviderException("EVP_PKEY_keygen_init failed");
                }

                // Set key size
                result = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize);
                if (result <= 0) {
                    throw new ProviderException("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
                }

                // Generate the key pair
                int pkeyPtr = OpenSSLCrypto.malloc(4);
                OpenSSLCrypto.memory().writeI32(pkeyPtr, 0);
                result = OpenSSLCrypto.EVP_PKEY_keygen(ctx, pkeyPtr);
                if (result <= 0) {
                    OpenSSLCrypto.free(pkeyPtr);
                    throw new ProviderException("EVP_PKEY_keygen failed");
                }

                int pkey = OpenSSLCrypto.memory().readInt(pkeyPtr);
                OpenSSLCrypto.free(pkeyPtr);
                if (pkey == 0) {
                    throw new ProviderException("Generated key is null");
                }

                try {
                    // Export private key to DER format (PKCS#8)
                    byte[] privateKeyBytes = OpenSSLCrypto.exportPrivateKey(pkey);
                    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

                    // Export public key to DER format (SubjectPublicKeyInfo / X.509)
                    byte[] publicKeyBytes = OpenSSLCrypto.exportPublicKey(pkey);
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

                    // Use standard KeyFactory to create the key objects
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                    return new KeyPair(publicKey, privateKey);

                } finally {
                    OpenSSLCrypto.EVP_PKEY_free(pkey);
                }

            } finally {
                OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
            }

        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error generating RSA key pair", e);
        }
    }
}
