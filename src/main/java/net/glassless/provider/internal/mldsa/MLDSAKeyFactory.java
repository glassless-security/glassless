package net.glassless.provider.internal.mldsa;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyFactory for ML-DSA keys.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.
 */
public class MLDSAKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec x509Spec) {
            return generatePublicFromEncoded(x509Spec.getEncoded());
        }
        throw new InvalidKeySpecException("Unsupported key spec: " +
            (keySpec == null ? "null" : keySpec.getClass().getName()));
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
            return generatePrivateFromEncoded(pkcs8Spec.getEncoded());
        }
        throw new InvalidKeySpecException("Unsupported key spec: " +
            (keySpec == null ? "null" : keySpec.getClass().getName()));
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key instanceof GlaSSLessMLDSAPublicKey pubKey) {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new X509EncodedKeySpec(pubKey.getEncoded());
            }
        } else if (key instanceof GlaSSLessMLDSAPrivateKey privKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new PKCS8EncodedKeySpec(privKey.getEncoded());
            }
        }
        throw new InvalidKeySpecException("Unsupported key type or spec: " +
            (key == null ? "null" : key.getClass().getName()) + " / " +
            (keySpec == null ? "null" : keySpec.getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof GlaSSLessMLDSAPublicKey || key instanceof GlaSSLessMLDSAPrivateKey) {
            return key;
        }

        if (key instanceof PublicKey pubKey) {
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(pubKey.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Failed to translate public key", e);
            }
        } else if (key instanceof PrivateKey privKey) {
            try {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Failed to translate private key", e);
            }
        }

        throw new InvalidKeyException("Unsupported key type: " +
            (key == null ? "null" : key.getClass().getName()));
    }

    private PublicKey generatePublicFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
            if (pkey.equals(MemorySegment.NULL)) {
                throw new InvalidKeySpecException("Failed to parse ML-DSA public key");
            }

            try {
                String algorithm = detectAlgorithmFromPublicKey(encoded);
                return new GlaSSLessMLDSAPublicKey(algorithm, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate ML-DSA public key", e);
        }
    }

    private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
            if (pkey.equals(MemorySegment.NULL)) {
                throw new InvalidKeySpecException("Failed to parse ML-DSA private key");
            }

            try {
                String algorithm = detectAlgorithmFromPrivateKey(encoded);
                return new GlaSSLessMLDSAPrivateKey(algorithm, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate ML-DSA private key", e);
        }
    }

    /**
     * Detects the ML-DSA variant from the encoded public key.
     * ML-DSA-44 OID: 2.16.840.1.101.3.4.3.17
     * ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18
     * ML-DSA-87 OID: 2.16.840.1.101.3.4.3.19
     */
    private String detectAlgorithmFromPublicKey(byte[] encoded) {
        // Look for OID pattern: 06 09 60 86 48 01 65 03 04 03 XX
        // where XX is 11 (44), 12 (65), or 13 (87)
        for (int i = 0; i < encoded.length - 10; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x09 &&
                encoded[i+2] == 0x60 && encoded[i+3] == (byte)0x86 &&
                encoded[i+4] == 0x48 && encoded[i+5] == 0x01 &&
                encoded[i+6] == 0x65 && encoded[i+7] == 0x03 &&
                encoded[i+8] == 0x04 && encoded[i+9] == 0x03) {
                return switch (encoded[i+10]) {
                    case 0x11 -> "ML-DSA-44";
                    case 0x12 -> "ML-DSA-65";
                    case 0x13 -> "ML-DSA-87";
                    default -> "ML-DSA";
                };
            }
        }
        return detectAlgorithmFromSize(encoded.length, true);
    }

    private String detectAlgorithmFromPrivateKey(byte[] encoded) {
        for (int i = 0; i < encoded.length - 10; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x09 &&
                encoded[i+2] == 0x60 && encoded[i+3] == (byte)0x86 &&
                encoded[i+4] == 0x48 && encoded[i+5] == 0x01 &&
                encoded[i+6] == 0x65 && encoded[i+7] == 0x03 &&
                encoded[i+8] == 0x04 && encoded[i+9] == 0x03) {
                return switch (encoded[i+10]) {
                    case 0x11 -> "ML-DSA-44";
                    case 0x12 -> "ML-DSA-65";
                    case 0x13 -> "ML-DSA-87";
                    default -> "ML-DSA";
                };
            }
        }
        return detectAlgorithmFromSize(encoded.length, false);
    }

    private String detectAlgorithmFromSize(int length, boolean isPublic) {
        // ML-DSA key sizes (approximate, includes encoding overhead):
        // ML-DSA-44: public ~1312 bytes, private ~2560 bytes
        // ML-DSA-65: public ~1952 bytes, private ~4032 bytes
        // ML-DSA-87: public ~2592 bytes, private ~4896 bytes
        if (isPublic) {
            if (length < 1600) return "ML-DSA-44";
            if (length < 2300) return "ML-DSA-65";
            return "ML-DSA-87";
        } else {
            if (length < 3000) return "ML-DSA-44";
            if (length < 4500) return "ML-DSA-65";
            return "ML-DSA-87";
        }
    }
}
