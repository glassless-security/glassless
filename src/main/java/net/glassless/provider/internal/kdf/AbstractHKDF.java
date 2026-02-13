package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for HKDF (HMAC-based Extract-and-Expand Key Derivation Function) implementations.
 * Implements RFC 5869 using OpenSSL's EVP_KDF API.
 */
public abstract class AbstractHKDF extends KDFSpi {

    private final String algorithm;
    private final String digestName;
    private final int hashLength;
    private final KDFParameters params;

    protected AbstractHKDF(KDFParameters params, String algorithm, String digestName, int hashLength)
            throws InvalidAlgorithmParameterException {
        super(params);
        this.params = params;
        this.algorithm = algorithm;
        this.digestName = digestName;
        this.hashLength = hashLength;
    }

    @Override
    protected KDFParameters engineGetParameters() {
        return params;
    }

    @Override
    protected SecretKey engineDeriveKey(String algorithm, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        byte[] derivedBytes = engineDeriveData(params);
        return new SecretKeySpec(derivedBytes, algorithm);
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof HKDFParameterSpec hkdfParams)) {
            throw new InvalidAlgorithmParameterException(
                "HKDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
        }

       try (Arena arena = Arena.ofConfined()) {
            return deriveHKDF(hkdfParams, arena);
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("HKDF derivation failed", e);
        }
    }

    private byte[] deriveHKDF(HKDFParameterSpec params, Arena arena) throws Throwable {
        // Fetch the HKDF KDF
        MemorySegment kdf = OpenSSLCrypto.EVP_KDF_fetch(MemorySegment.NULL, "HKDF", MemorySegment.NULL, arena);
        if (kdf == null || kdf.address() == 0) {
            throw new ProviderException("Failed to fetch HKDF KDF");
        }

        try {
            // Create KDF context
            MemorySegment ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
            if (ctx == null || ctx.address() == 0) {
                throw new ProviderException("Failed to create HKDF context");
            }

            try {
                // Determine the mode and derive
               return switch (params) {
                  case HKDFParameterSpec.Extract extract ->
                     // Extract only
                     deriveExtract(ctx, extract, arena);
                  case HKDFParameterSpec.Expand expand ->
                     // Expand only
                     deriveExpand(ctx, expand, arena);
                  case HKDFParameterSpec.ExtractThenExpand extractExpand ->
                     // Extract and Expand
                     deriveExtractExpand(ctx, extractExpand, arena);
                  default -> throw new InvalidAlgorithmParameterException(
                     "Unsupported HKDFParameterSpec type: " + params.getClass().getName());
               };
            } finally {
                OpenSSLCrypto.EVP_KDF_CTX_free(ctx);
            }
        } finally {
            OpenSSLCrypto.EVP_KDF_free(kdf);
        }
    }

    private byte[] deriveExtract(MemorySegment ctx, HKDFParameterSpec.Extract params, Arena arena) throws Throwable {
        // Get IKM from extracting all IKM values
        byte[] ikm = concatenateKeys(params.ikms());
        byte[] salt = concatenateKeys(params.salts());
        if (salt.length == 0) {
            salt = new byte[hashLength];  // Use zeros if no salt
        }

        // Build OSSL_PARAM array for extract
        MemorySegment osslParams = OpenSSLCrypto.createHKDFParams(
            digestName,
            OpenSSLCrypto.HKDF_MODE_EXTRACT_ONLY,
            salt,
            ikm,
            null,  // No info for extract
            arena
        );

        // PRK output length is the hash length
        MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, hashLength);

        int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, hashLength, osslParams);
        if (result != 1) {
            throw new ProviderException("HKDF extract failed");
        }

        byte[] prk = new byte[hashLength];
        output.asByteBuffer().get(prk);
        return prk;
    }

    private byte[] deriveExpand(MemorySegment ctx, HKDFParameterSpec.Expand params, Arena arena) throws Throwable {
        // Get PRK from the SecretKey
        SecretKey prkKey = params.prk();
        byte[] prk = prkKey.getEncoded();
        byte[] info = params.info();
        if (info == null) info = new byte[0];
        int length = params.length();

        // Build OSSL_PARAM array for expand
        MemorySegment osslParams = OpenSSLCrypto.createHKDFParams(
            digestName,
            OpenSSLCrypto.HKDF_MODE_EXPAND_ONLY,
            null,  // No salt for expand
            prk,   // Use PRK as key
            info,
            arena
        );

        // Derive the output
        MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, length);

        int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
        if (result != 1) {
            throw new ProviderException("HKDF expand failed");
        }

        byte[] derived = new byte[length];
        output.asByteBuffer().get(derived);
        return derived;
    }

    private byte[] deriveExtractExpand(MemorySegment ctx, HKDFParameterSpec.ExtractThenExpand params, Arena arena) throws Throwable {
        // Get IKM, salt, info
        byte[] ikm = concatenateKeys(params.ikms());
        byte[] salt = concatenateKeys(params.salts());
        if (salt.length == 0) {
            salt = new byte[hashLength];  // Use zeros if no salt
        }
        byte[] info = params.info();
        if (info == null) info = new byte[0];
        int length = params.length();

        // Build OSSL_PARAM array for extract+expand
        MemorySegment osslParams = OpenSSLCrypto.createHKDFParams(
            digestName,
            OpenSSLCrypto.HKDF_MODE_EXTRACT_AND_EXPAND,
            salt,
            ikm,
            info,
            arena
        );

        // Derive the output
        MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, length);

        int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
        if (result != 1) {
            throw new ProviderException("HKDF extract+expand failed");
        }

        byte[] derived = new byte[length];
        output.asByteBuffer().get(derived);
        return derived;
    }

    private byte[] concatenateKeys(List<SecretKey> keys) {
        if (keys == null || keys.isEmpty()) {
            return new byte[0];
        }
        if (keys.size() == 1) {
            return keys.get(0).getEncoded();
        }

        // Calculate total length
        int totalLength = 0;
        for (SecretKey key : keys) {
            totalLength += key.getEncoded().length;
        }

        // Concatenate all keys
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (SecretKey key : keys) {
            byte[] encoded = key.getEncoded();
            System.arraycopy(encoded, 0, result, offset, encoded.length);
            offset += encoded.length;
        }

        return result;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
