package net.glassless.provider.internal.algparamgen;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AlgorithmParameterGenerator for Diffie-Hellman.
 * Generates DH domain parameters (p, g) using OpenSSL.
 */
public class DHParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private int primeSize = 2048;  // Default prime size
    private int exponentSize = 256; // Default private value length
    private SecureRandom random;

    @Override
    protected void engineInit(int size, SecureRandom random) {
        // Validate size
        if (size < 512 || size > 8192) {
            throw new InvalidParameterException("Prime size must be between 512 and 8192 bits");
        }
        if (size % 64 != 0) {
            throw new InvalidParameterException("Prime size must be a multiple of 64");
        }

        this.primeSize = size;
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (genParamSpec instanceof DHGenParameterSpec dhGenSpec) {
            this.primeSize = dhGenSpec.getPrimeSize();
            this.exponentSize = dhGenSpec.getExponentSize();
            this.random = random;
        } else {
            throw new InvalidAlgorithmParameterException(
                "Unsupported parameter spec: " + (genParamSpec == null ? "null" : genParamSpec.getClass().getName()));
        }
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        try (Arena arena = Arena.ofConfined()) {
            // Create EVP_PKEY_CTX for DH parameter generation
            MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
                MemorySegment.NULL,
                "DH",
                MemorySegment.NULL,
                arena
            );
            if (ctx == null || ctx.address() == 0) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for DH");
            }

            try {
                // Initialize for parameter generation
                int result = OpenSSLCrypto.EVP_PKEY_paramgen_init(ctx);
                if (result != 1) {
                    throw new ProviderException("EVP_PKEY_paramgen_init failed");
                }

                // Set the prime length
                result = OpenSSLCrypto.EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, primeSize);
                if (result != 1) {
                    throw new ProviderException("Failed to set DH prime length");
                }

                // Set the generator (typically 2)
                result = OpenSSLCrypto.EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2);
                if (result != 1) {
                    throw new ProviderException("Failed to set DH generator");
                }

                // Generate parameters
                MemorySegment pkeyPtr = arena.allocate(ValueLayout.ADDRESS);
                result = OpenSSLCrypto.EVP_PKEY_paramgen(ctx, pkeyPtr);
                if (result != 1) {
                    throw new ProviderException("EVP_PKEY_paramgen failed");
                }

                MemorySegment pkey = pkeyPtr.get(ValueLayout.ADDRESS, 0);
                if (pkey.address() == 0) {
                    throw new ProviderException("Generated parameter key is null");
                }

                try {
                    // Extract p and g from the generated parameters
                    BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p", arena);
                    BigInteger g = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "g", arena);

                    // Create DHParameterSpec
                    DHParameterSpec dhSpec;
                    if (exponentSize > 0) {
                        dhSpec = new DHParameterSpec(p, g, exponentSize);
                    } else {
                        dhSpec = new DHParameterSpec(p, g);
                    }

                    // Create and initialize AlgorithmParameters
                    AlgorithmParameters params = AlgorithmParameters.getInstance("DH", "Glassless");
                    params.init(dhSpec);

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
            throw new ProviderException("Error generating DH parameters", e);
        }
    }
}
