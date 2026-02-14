package net.glassless.provider.internal.eddsa;

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
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyPairGenerator for EdDSA (Ed25519 and Ed448).
 */
public class EdDSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private NamedParameterSpec params = NamedParameterSpec.ED25519;  // Default to Ed25519
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // EdDSA doesn't use key size, use algorithm-based initialization
        if (keysize == 255 || keysize == 256) {
            this.params = NamedParameterSpec.ED25519;
        } else if (keysize == 448 || keysize == 456) {
            this.params = NamedParameterSpec.ED448;
        } else {
            throw new InvalidParameterException(
                "EdDSA key size must be 255/256 (Ed25519) or 448/456 (Ed448), got: " + keysize);
        }
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof NamedParameterSpec nps) {
            String name = nps.getName();
            if ("Ed25519".equalsIgnoreCase(name)) {
                this.params = NamedParameterSpec.ED25519;
            } else if ("Ed448".equalsIgnoreCase(name)) {
                this.params = NamedParameterSpec.ED448;
            } else {
                throw new InvalidAlgorithmParameterException(
                    "Unsupported EdDSA curve: " + name + ". Supported: Ed25519, Ed448");
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
        }
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        String algorithmName = params.getName().toUpperCase();  // ED25519 or ED448

        try (Arena arena = Arena.ofConfined()) {
            // Create EVP_PKEY_CTX for EdDSA key generation
            MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
                MemorySegment.NULL,
                algorithmName,
                MemorySegment.NULL,
                arena
            );
            if (ctx == null || ctx.address() == 0) {
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
                if (pkey.address() == 0) {
                    throw new ProviderException("Generated key is null");
                }

                try {
                    // Export keys in DER format
                    byte[] publicKeyEncoded = OpenSSLCrypto.exportPublicKey(pkey, arena);
                    byte[] privateKeyEncoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);

                    // Extract raw key bytes for EdECPoint
                    byte[] rawPublicKey = extractRawPublicKey(publicKeyEncoded, algorithmName);
                    byte[] rawPrivateKey = extractRawPrivateKey(privateKeyEncoded, algorithmName);

                    // Create EdECPoint from raw public key
                    EdECPoint point = createEdECPoint(rawPublicKey);

                    // Create key objects
                    GlaSSLessEdECPublicKey publicKey = new GlaSSLessEdECPublicKey(params, point, publicKeyEncoded);
                    GlaSSLessEdECPrivateKey privateKey = new GlaSSLessEdECPrivateKey(params, rawPrivateKey, privateKeyEncoded);

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
            throw new ProviderException("Error generating EdDSA key pair", e);
        }
    }

    /**
     * Extracts the raw public key bytes from X.509 encoded key.
     * Ed25519: 32 bytes, Ed448: 57 bytes
     */
    private byte[] extractRawPublicKey(byte[] encoded, String algorithm) {
        // X.509 SubjectPublicKeyInfo structure for EdDSA:
        // SEQUENCE { AlgorithmIdentifier, BIT STRING { raw key } }
        // The raw key is at the end after the BIT STRING header
        int keyLen = algorithm.equals("ED25519") ? 32 : 57;
        byte[] raw = new byte[keyLen];
        // The raw key is the last keyLen bytes (after the BIT STRING unused bits byte)
        System.arraycopy(encoded, encoded.length - keyLen, raw, 0, keyLen);
        return raw;
    }

    /**
     * Extracts the raw private key bytes from PKCS#8 encoded key.
     * Ed25519: 32 bytes, Ed448: 57 bytes
     */
    private byte[] extractRawPrivateKey(byte[] encoded, String algorithm) {
        // PKCS#8 PrivateKeyInfo structure for EdDSA:
        // SEQUENCE { INTEGER version, AlgorithmIdentifier, OCTET STRING { OCTET STRING { raw key } } }
        int keyLen = algorithm.equals("ED25519") ? 32 : 57;
        byte[] raw = new byte[keyLen];
        // The raw key is typically at the end, wrapped in OCTET STRING
        // For Ed25519: encoded length is 48, raw key at offset 16
        // For Ed448: encoded length is 73, raw key at offset 16
        System.arraycopy(encoded, encoded.length - keyLen, raw, 0, keyLen);
        return raw;
    }

    /**
     * Creates an EdECPoint from raw public key bytes.
     * The point is represented as the y-coordinate with the sign of x in the MSB.
     */
    private EdECPoint createEdECPoint(byte[] raw) {
        // EdDSA encodes the point as: y-coordinate with x sign in MSB
        // We need to reverse the bytes (little-endian to big-endian)
        byte[] reversed = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) {
            reversed[i] = raw[raw.length - 1 - i];
        }

        // The MSB of the last byte (now first) contains the sign of x
        boolean xOdd = (reversed[0] & 0x80) != 0;
        reversed[0] &= 0x7F;  // Clear the sign bit

        // Convert to BigInteger for y-coordinate
        BigInteger y = new BigInteger(1, reversed);

        return new EdECPoint(xOdd, y);
    }
}
