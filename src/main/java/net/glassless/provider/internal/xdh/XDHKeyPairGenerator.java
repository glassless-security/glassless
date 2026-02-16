package net.glassless.provider.internal.xdh;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
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
 * KeyPairGenerator for XDH (X25519 and X448).
 */
public class XDHKeyPairGenerator extends KeyPairGeneratorSpi {

    private NamedParameterSpec params = NamedParameterSpec.X25519;  // Default to X25519
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // XDH doesn't use key size, use algorithm-based initialization
        if (keysize == 255 || keysize == 256) {
            this.params = NamedParameterSpec.X25519;
        } else if (keysize == 448 || keysize == 456) {
            this.params = NamedParameterSpec.X448;
        } else {
            throw new InvalidParameterException(
                "XDH key size must be 255/256 (X25519) or 448/456 (X448), got: " + keysize);
        }
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof NamedParameterSpec nps) {
            String name = nps.getName();
            if ("X25519".equalsIgnoreCase(name)) {
                this.params = NamedParameterSpec.X25519;
            } else if ("X448".equalsIgnoreCase(name)) {
                this.params = NamedParameterSpec.X448;
            } else {
                throw new InvalidAlgorithmParameterException(
                    "Unsupported XDH curve: " + name + ". Supported: X25519, X448");
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
        }
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        String algorithmName = params.getName().toUpperCase();  // X25519 or X448

        try (Arena arena = Arena.ofConfined()) {
            // Create EVP_PKEY_CTX for XDH key generation
            MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
                MemorySegment.NULL,
                algorithmName,
                MemorySegment.NULL,
                arena
            );
            if (ctx.equals(MemorySegment.NULL)) {
                throw new ProviderException("Failed to create EVP_PKEY_CTX for " + algorithmName);
            }

            try {
                // Initialize for key generation
                int result = OpenSSLCrypto.EVP_PKEY_keygen_init(ctx);
                if (result != 1) {
                    throw new ProviderException("EVP_PKEY_keygen_init failed for " + algorithmName);
                }

                // Generate the key pair
                MemorySegment pkeyPtr = arena.allocate(ValueLayout.ADDRESS);
                result = OpenSSLCrypto.EVP_PKEY_keygen(ctx, pkeyPtr);
                if (result != 1) {
                    throw new ProviderException("EVP_PKEY_keygen failed for " + algorithmName);
                }

                MemorySegment pkey = pkeyPtr.get(ValueLayout.ADDRESS, 0);
                if (pkey.equals(MemorySegment.NULL)) {
                    throw new ProviderException("Generated key is null");
                }

                try {
                    // Export keys in DER format
                    byte[] publicKeyEncoded = OpenSSLCrypto.exportPublicKey(pkey, arena);
                    byte[] privateKeyEncoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);

                    // Extract raw key bytes
                    int keyLen = algorithmName.equals("X25519") ? 32 : 56;
                    byte[] rawPublicKey = extractRawPublicKey(publicKeyEncoded, keyLen);
                    byte[] rawPrivateKey = extractRawPrivateKey(privateKeyEncoded, keyLen);

                    // Create u-coordinate from raw public key (little-endian)
                    BigInteger u = createUCoordinate(rawPublicKey);

                    // Create key objects
                    GlaSSLessXECPublicKey publicKey = new GlaSSLessXECPublicKey(params, u, publicKeyEncoded);
                    GlaSSLessXECPrivateKey privateKey = new GlaSSLessXECPrivateKey(params, rawPrivateKey, privateKeyEncoded);

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
            throw new ProviderException("Error generating XDH key pair", e);
        }
    }

    /**
     * Extracts the raw public key bytes from X.509 encoded key.
     */
    private byte[] extractRawPublicKey(byte[] encoded, int keyLen) {
        byte[] raw = new byte[keyLen];
        System.arraycopy(encoded, encoded.length - keyLen, raw, 0, keyLen);
        return raw;
    }

    /**
     * Extracts the raw private key bytes from PKCS#8 encoded key.
     */
    private byte[] extractRawPrivateKey(byte[] encoded, int keyLen) {
        byte[] raw = new byte[keyLen];
        System.arraycopy(encoded, encoded.length - keyLen, raw, 0, keyLen);
        return raw;
    }

    /**
     * Creates a BigInteger u-coordinate from raw public key bytes (little-endian).
     */
    private BigInteger createUCoordinate(byte[] raw) {
        // XDH uses little-endian encoding, reverse for BigInteger
        byte[] reversed = new byte[raw.length + 1];  // +1 for sign byte
        reversed[0] = 0;  // Ensure positive
        for (int i = 0; i < raw.length; i++) {
            reversed[i + 1] = raw[raw.length - 1 - i];
        }
        return new BigInteger(reversed);
    }
}
