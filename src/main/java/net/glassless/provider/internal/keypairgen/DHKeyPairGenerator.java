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
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.DHParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * DH (Diffie-Hellman) KeyPairGenerator using OpenSSL.
 * DH key generation requires a two-step process:
 * 1. Generate DH parameters (p, g)
 * 2. Generate the key pair from those parameters
 */
public class DHKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int DEFAULT_KEY_SIZE = 2048;
    private static final int MIN_KEY_SIZE = 512;
    private static final int MAX_KEY_SIZE = 8192;

    private int keySize = DEFAULT_KEY_SIZE;
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize < MIN_KEY_SIZE || keysize > MAX_KEY_SIZE) {
            throw new InvalidParameterException("Key size must be between " + MIN_KEY_SIZE + " and " + MAX_KEY_SIZE + " bits");
        }
        // DH key sizes should be multiples of 64
        if (keysize % 64 != 0) {
            throw new InvalidParameterException("DH key size must be a multiple of 64");
        }
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof DHParameterSpec dhParams) {
            // Extract key size from the P parameter
            int pBitLength = dhParams.getP().bitLength();
            if (pBitLength < MIN_KEY_SIZE || pBitLength > MAX_KEY_SIZE) {
                throw new InvalidAlgorithmParameterException("Key size must be between " + MIN_KEY_SIZE + " and " + MAX_KEY_SIZE + " bits");
            }
            this.keySize = pBitLength;
            this.random = random;
        } else if (params != null) {
            throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // Step 1: Generate DH parameters
            int paramCtx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(0, "DH", 0);
            if (paramCtx == 0) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for DH parameter generation");
            }

            int dhParams;
            try {
                // Initialize for parameter generation
                int result = OpenSSLCrypto.EVP_PKEY_paramgen_init(paramCtx);
                if (result <= 0) {
                    throw new ProviderException("EVP_PKEY_paramgen_init failed");
                }

                // Set key size
                result = OpenSSLCrypto.EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramCtx, keySize);
                if (result <= 0) {
                    throw new ProviderException("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");
                }

                // Generate parameters
                int paramsPtr = OpenSSLCrypto.malloc(4);
                OpenSSLCrypto.memory().writeI32(paramsPtr, 0);
                result = OpenSSLCrypto.EVP_PKEY_paramgen(paramCtx, paramsPtr);
                if (result <= 0) {
                    OpenSSLCrypto.free(paramsPtr);
                    throw new ProviderException("EVP_PKEY_paramgen failed");
                }

                dhParams = OpenSSLCrypto.memory().readInt(paramsPtr);
                OpenSSLCrypto.free(paramsPtr);
                if (dhParams == 0) {
                    throw new ProviderException("Generated DH parameters are null");
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_CTX_free(paramCtx);
            }

            // Step 2: Generate the key pair from parameters
            try {
                int keyCtx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(0, dhParams, 0);
                if (keyCtx == 0) {
                    throw new ProviderException("Failed to create EVP_PKEY_CTX for DH key generation");
                }

                try {
                    // Initialize for key generation
                    int result = OpenSSLCrypto.EVP_PKEY_keygen_init(keyCtx);
                    if (result <= 0) {
                        throw new ProviderException("EVP_PKEY_keygen_init failed");
                    }

                    // Generate the key pair
                    int pkeyPtr = OpenSSLCrypto.malloc(4);
                    OpenSSLCrypto.memory().writeI32(pkeyPtr, 0);
                    result = OpenSSLCrypto.EVP_PKEY_keygen(keyCtx, pkeyPtr);
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
                        KeyFactory keyFactory = KeyFactory.getInstance("DH");
                        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                        return new KeyPair(publicKey, privateKey);

                    } finally {
                        OpenSSLCrypto.EVP_PKEY_free(pkey);
                    }

                } finally {
                    OpenSSLCrypto.EVP_PKEY_CTX_free(keyCtx);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(dhParams);
            }

        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error generating DH key pair", e);
        }
    }
}
