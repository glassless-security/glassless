package net.glassless.provider.internal.algparamgen;

import java.math.BigInteger;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAGenParameterSpec;
import java.security.spec.DSAParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AlgorithmParameterGenerator for DSA.
 * Generates DSA domain parameters (p, q, g) using OpenSSL.
 */
public class DSAParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private int primePBits = 2048;  // Default key size
    private int primeQBits = 256;   // Default q size
    private SecureRandom random;

    @Override
    protected void engineInit(int size, SecureRandom random) {
        // Validate size
        if (size < 512 || size > 8192) {
            throw new InvalidParameterException("Key size must be between 512 and 8192 bits");
        }
        if (size % 64 != 0) {
            throw new InvalidParameterException("Key size must be a multiple of 64");
        }

        this.primePBits = size;
        // Set Q size based on P size (following FIPS 186-4)
        if (size <= 1024) {
            this.primeQBits = 160;
        } else if (size <= 2048) {
            this.primeQBits = 256;
        } else {
            this.primeQBits = 256; // For larger sizes, use 256-bit Q
        }
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (genParamSpec instanceof DSAGenParameterSpec dsaGenSpec) {
            this.primePBits = dsaGenSpec.getPrimePLength();
            this.primeQBits = dsaGenSpec.getSubprimeQLength();
            this.random = random;
        } else {
            throw new InvalidAlgorithmParameterException(
                "Unsupported parameter spec: " + (genParamSpec == null ? "null" : genParamSpec.getClass().getName()));
        }
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        try {
            // Create EVP_PKEY_CTX for DSA parameter generation
            int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
                0,
                "DSA",
                0
            );
            if (ctx == 0) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for DSA");
            }

            try {
                // Initialize for parameter generation
                int result = OpenSSLCrypto.EVP_PKEY_paramgen_init(ctx);
                if (result != 1) {
                    throw new ProviderException("EVP_PKEY_paramgen_init failed");
                }

                // Set the key size (pbits)
                result = OpenSSLCrypto.EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, primePBits);
                if (result != 1) {
                    throw new ProviderException("Failed to set DSA key size");
                }

                // Set the Q size (qbits)
                result = OpenSSLCrypto.EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, primeQBits);
                if (result != 1) {
                    throw new ProviderException("Failed to set DSA Q size");
                }

                // Generate parameters using pointer-to-pointer pattern
                int pkeyPtr = OpenSSLCrypto.malloc(4);
                OpenSSLCrypto.memory().writeI32(pkeyPtr, 0);
                result = OpenSSLCrypto.EVP_PKEY_paramgen(ctx, pkeyPtr);
                if (result != 1) {
                    OpenSSLCrypto.free(pkeyPtr);
                    throw new ProviderException("EVP_PKEY_paramgen failed");
                }

                int pkey = OpenSSLCrypto.memory().readInt(pkeyPtr);
                OpenSSLCrypto.free(pkeyPtr);
                if (pkey == 0) {
                    throw new ProviderException("Generated parameter key is null");
                }

                try {
                    // Extract p, q, g from the generated parameters
                    BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p");
                    BigInteger q = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "q");
                    BigInteger g = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "g");

                    // Create DSAParameterSpec
                    DSAParameterSpec dsaSpec = new DSAParameterSpec(p, q, g);

                    // Create and initialize AlgorithmParameters
                    AlgorithmParameters params = AlgorithmParameters.getInstance("DSA", "GlaSSLess");
                    params.init(dsaSpec);

                    return params;
                } finally {
                    OpenSSLCrypto.EVP_PKEY_free(pkey);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error generating DSA parameters", e);
        }
    }
}
