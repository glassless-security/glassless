package net.glassless.provider.internal.slhdsa;

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
 * KeyPairGenerator for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm).
 * Supports 12 variants based on hash (SHA2/SHAKE), security level (128/192/256),
 * and speed/size tradeoff (s/f).
 *
 * <p>SLH-DSA is standardized in FIPS 205 and requires OpenSSL 3.5+.
 */
public class SLHDSAKeyPairGenerator extends KeyPairGeneratorSpi {

    // OpenSSL algorithm names (using hyphenated format for OpenSSL 3.5+)
    public static final String SHA2_128S = "SLH-DSA-SHA2-128s";
    public static final String SHA2_128F = "SLH-DSA-SHA2-128f";
    public static final String SHA2_192S = "SLH-DSA-SHA2-192s";
    public static final String SHA2_192F = "SLH-DSA-SHA2-192f";
    public static final String SHA2_256S = "SLH-DSA-SHA2-256s";
    public static final String SHA2_256F = "SLH-DSA-SHA2-256f";
    public static final String SHAKE_128S = "SLH-DSA-SHAKE-128s";
    public static final String SHAKE_128F = "SLH-DSA-SHAKE-128f";
    public static final String SHAKE_192S = "SLH-DSA-SHAKE-192s";
    public static final String SHAKE_192F = "SLH-DSA-SHAKE-192f";
    public static final String SHAKE_256S = "SLH-DSA-SHAKE-256s";
    public static final String SHAKE_256F = "SLH-DSA-SHAKE-256f";

    protected String algorithmName = SHA2_128F;  // Default
    protected String jcaAlgorithm = "SLH-DSA-SHA2-128f";
    protected SecureRandom random;

    public SLHDSAKeyPairGenerator() {
        // Default constructor
    }

    protected SLHDSAKeyPairGenerator(String algorithmName, String jcaAlgorithm) {
        this.algorithmName = algorithmName;
        this.jcaAlgorithm = jcaAlgorithm;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // Map security levels to default variants (using SHA2 and 'f' for faster signing)
        switch (keysize) {
            case 128 -> {
                this.algorithmName = SHA2_128F;
                this.jcaAlgorithm = "SLH-DSA-SHA2-128f";
            }
            case 192 -> {
                this.algorithmName = SHA2_192F;
                this.jcaAlgorithm = "SLH-DSA-SHA2-192f";
            }
            case 256 -> {
                this.algorithmName = SHA2_256F;
                this.jcaAlgorithm = "SLH-DSA-SHA2-256f";
            }
            default -> throw new InvalidParameterException(
                "Invalid SLH-DSA security level. Use 128, 192, or 256");
        }
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof NamedParameterSpec nps) {
            String name = normalizeAlgorithmName(nps.getName());
            setAlgorithm(name);
        } else {
            throw new InvalidAlgorithmParameterException(
                "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
        }
        this.random = random;
    }

    protected void setAlgorithm(String normalizedName) throws InvalidAlgorithmParameterException {
        switch (normalizedName) {
            case "SLHDSASHA2128S" -> {
                this.algorithmName = SHA2_128S;
                this.jcaAlgorithm = "SLH-DSA-SHA2-128s";
            }
            case "SLHDSASHA2128F" -> {
                this.algorithmName = SHA2_128F;
                this.jcaAlgorithm = "SLH-DSA-SHA2-128f";
            }
            case "SLHDSASHA2192S" -> {
                this.algorithmName = SHA2_192S;
                this.jcaAlgorithm = "SLH-DSA-SHA2-192s";
            }
            case "SLHDSASHA2192F" -> {
                this.algorithmName = SHA2_192F;
                this.jcaAlgorithm = "SLH-DSA-SHA2-192f";
            }
            case "SLHDSASHA2256S" -> {
                this.algorithmName = SHA2_256S;
                this.jcaAlgorithm = "SLH-DSA-SHA2-256s";
            }
            case "SLHDSASHA2256F" -> {
                this.algorithmName = SHA2_256F;
                this.jcaAlgorithm = "SLH-DSA-SHA2-256f";
            }
            case "SLHDSASHAKE128S" -> {
                this.algorithmName = SHAKE_128S;
                this.jcaAlgorithm = "SLH-DSA-SHAKE-128s";
            }
            case "SLHDSASHAKE128F" -> {
                this.algorithmName = SHAKE_128F;
                this.jcaAlgorithm = "SLH-DSA-SHAKE-128f";
            }
            case "SLHDSASHAKE192S" -> {
                this.algorithmName = SHAKE_192S;
                this.jcaAlgorithm = "SLH-DSA-SHAKE-192s";
            }
            case "SLHDSASHAKE192F" -> {
                this.algorithmName = SHAKE_192F;
                this.jcaAlgorithm = "SLH-DSA-SHAKE-192f";
            }
            case "SLHDSASHAKE256S" -> {
                this.algorithmName = SHAKE_256S;
                this.jcaAlgorithm = "SLH-DSA-SHAKE-256s";
            }
            case "SLHDSASHAKE256F" -> {
                this.algorithmName = SHAKE_256F;
                this.jcaAlgorithm = "SLH-DSA-SHAKE-256f";
            }
            default -> throw new InvalidAlgorithmParameterException(
                "Unsupported SLH-DSA variant: " + normalizedName);
        }
    }

    private String normalizeAlgorithmName(String name) {
        return name.toUpperCase().replace("-", "").replace("_", "");
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // Create EVP_PKEY_CTX for SLH-DSA key generation
            int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
                0,
                algorithmName,
                0
            );
            if (ctx == 0) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for " + algorithmName +
                    ". SLH-DSA requires OpenSSL 3.5+");
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
                        GlaSSLessSLHDSAPublicKey publicKey = new GlaSSLessSLHDSAPublicKey(jcaAlgorithm, publicKeyEncoded);
                        GlaSSLessSLHDSAPrivateKey privateKey = new GlaSSLessSLHDSAPrivateKey(jcaAlgorithm, privateKeyEncoded);

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
            throw new ProviderException("Error generating SLH-DSA key pair", e);
        }
    }
}
