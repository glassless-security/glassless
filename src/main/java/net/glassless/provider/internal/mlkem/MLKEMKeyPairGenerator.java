package net.glassless.provider.internal.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyPairGenerator for ML-KEM (Module-Lattice Key Encapsulation Mechanism).
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 variants.
 *
 * <p>ML-KEM is standardized in FIPS 203 and requires OpenSSL 3.5+.
 */
public class MLKEMKeyPairGenerator extends KeyPairGeneratorSpi {

    // OpenSSL algorithm names
    protected static final String MLKEM512 = "mlkem512";
    protected static final String MLKEM768 = "mlkem768";
    protected static final String MLKEM1024 = "mlkem1024";

    protected String algorithmName = MLKEM768;  // Default to ML-KEM-768
    protected String jcaAlgorithm = "ML-KEM-768";
    protected SecureRandom random;

    public MLKEMKeyPairGenerator() {
        // Default constructor
    }

    protected MLKEMKeyPairGenerator(String algorithmName, String jcaAlgorithm) {
        this.algorithmName = algorithmName;
        this.jcaAlgorithm = jcaAlgorithm;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // ML-KEM uses security strength levels, not key sizes
        // Map security levels: 128 -> 512, 192 -> 768, 256 -> 1024
        switch (keysize) {
            case 128, 512 -> {
                this.algorithmName = MLKEM512;
                this.jcaAlgorithm = "ML-KEM-512";
            }
            case 192, 768 -> {
                this.algorithmName = MLKEM768;
                this.jcaAlgorithm = "ML-KEM-768";
            }
            case 256, 1024 -> {
                this.algorithmName = MLKEM1024;
                this.jcaAlgorithm = "ML-KEM-1024";
            }
            default -> throw new InvalidParameterException(
                "Invalid ML-KEM parameter. Use 512, 768, or 1024 (or security levels 128, 192, 256)");
        }
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof NamedParameterSpec nps) {
            String name = nps.getName().toUpperCase().replace("-", "").replace("_", "");
            switch (name) {
                case "MLKEM512" -> {
                    this.algorithmName = MLKEM512;
                    this.jcaAlgorithm = "ML-KEM-512";
                }
                case "MLKEM768" -> {
                    this.algorithmName = MLKEM768;
                    this.jcaAlgorithm = "ML-KEM-768";
                }
                case "MLKEM1024" -> {
                    this.algorithmName = MLKEM1024;
                    this.jcaAlgorithm = "ML-KEM-1024";
                }
                default -> throw new InvalidAlgorithmParameterException(
                    "Unsupported ML-KEM variant: " + nps.getName() + ". Supported: ML-KEM-512, ML-KEM-768, ML-KEM-1024");
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
        }
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // Create EVP_PKEY_CTX for ML-KEM key generation
            int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
                0,
                algorithmName,
                0
            );
            if (ctx == 0) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for " + algorithmName +
                    ". ML-KEM requires OpenSSL 3.5+");
            }

            try {
                // Initialize for key generation
                int result = OpenSSLCrypto.EVP_PKEY_keygen_init(ctx);
                if (result != 1) {
                    throw new ProviderException("EVP_PKEY_keygen_init failed for " + algorithmName);
                }

                // Generate the key pair
                int pkeyPtr = OpenSSLCrypto.malloc(4);
                try {
                    OpenSSLCrypto.memory().writeI32(pkeyPtr, 0);
                    result = OpenSSLCrypto.EVP_PKEY_keygen(ctx, pkeyPtr);
                    if (result != 1) {
                        throw new ProviderException("EVP_PKEY_keygen failed for " + algorithmName);
                    }

                    int pkey = OpenSSLCrypto.memory().readInt(pkeyPtr);
                    if (pkey == 0) {
                        throw new ProviderException("Generated key is null");
                    }

                    try {
                        // Export keys in DER format
                        byte[] publicKeyEncoded = OpenSSLCrypto.exportPublicKey(pkey);
                        byte[] privateKeyEncoded = OpenSSLCrypto.exportPrivateKey(pkey);

                        // Create key objects
                        GlaSSLessMLKEMPublicKey publicKey = new GlaSSLessMLKEMPublicKey(jcaAlgorithm, publicKeyEncoded);
                        GlaSSLessMLKEMPrivateKey privateKey = new GlaSSLessMLKEMPrivateKey(jcaAlgorithm, privateKeyEncoded);

                        return new KeyPair(publicKey, privateKey);
                    } finally {
                        OpenSSLCrypto.EVP_PKEY_free(pkey);
                    }
                } finally {
                    OpenSSLCrypto.free(pkeyPtr);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error generating ML-KEM key pair", e);
        }
    }
}
