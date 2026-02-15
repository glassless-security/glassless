package net.glassless.provider.internal.mlkem;

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
 * KeyFactory for ML-KEM keys.
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
 */
public class MLKEMKeyFactory extends KeyFactorySpi {

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
        if (key instanceof GlaSSLessMLKEMPublicKey pubKey) {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new X509EncodedKeySpec(pubKey.getEncoded());
            }
        } else if (key instanceof GlaSSLessMLKEMPrivateKey privKey) {
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
        if (key instanceof GlaSSLessMLKEMPublicKey || key instanceof GlaSSLessMLKEMPrivateKey) {
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
            // Load the key with OpenSSL to validate
            MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
            if (pkey == null || pkey.address() == 0) {
                throw new InvalidKeySpecException("Failed to parse ML-KEM public key");
            }

            try {
                String algorithm = detectAlgorithmFromPublicKey(encoded);
                return new GlaSSLessMLKEMPublicKey(algorithm, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate ML-KEM public key", e);
        }
    }

    private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try (Arena arena = Arena.ofConfined()) {
            // Load the key with OpenSSL to validate
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
            if (pkey == null || pkey.address() == 0) {
                throw new InvalidKeySpecException("Failed to parse ML-KEM private key");
            }

            try {
                String algorithm = detectAlgorithmFromPrivateKey(encoded);
                return new GlaSSLessMLKEMPrivateKey(algorithm, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate ML-KEM private key", e);
        }
    }

    /**
     * Detects the ML-KEM variant from the encoded public key.
     * ML-KEM-512 OID: 2.16.840.1.101.3.4.4.1
     * ML-KEM-768 OID: 2.16.840.1.101.3.4.4.2
     * ML-KEM-1024 OID: 2.16.840.1.101.3.4.4.3
     */
    private String detectAlgorithmFromPublicKey(byte[] encoded) {
        // Look for OID pattern: 06 09 60 86 48 01 65 03 04 04 XX
        // where XX is 01 (512), 02 (768), or 03 (1024)
        for (int i = 0; i < encoded.length - 10; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x09 &&
                encoded[i+2] == 0x60 && encoded[i+3] == (byte)0x86 &&
                encoded[i+4] == 0x48 && encoded[i+5] == 0x01 &&
                encoded[i+6] == 0x65 && encoded[i+7] == 0x03 &&
                encoded[i+8] == 0x04 && encoded[i+9] == 0x04) {
                return switch (encoded[i+10]) {
                    case 0x01 -> "ML-KEM-512";
                    case 0x02 -> "ML-KEM-768";
                    case 0x03 -> "ML-KEM-1024";
                    default -> "ML-KEM";
                };
            }
        }
        // Fall back based on size heuristics
        return detectAlgorithmFromSize(encoded.length, true);
    }

    private String detectAlgorithmFromPrivateKey(byte[] encoded) {
        // Look for same OID pattern in private key
        for (int i = 0; i < encoded.length - 10; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x09 &&
                encoded[i+2] == 0x60 && encoded[i+3] == (byte)0x86 &&
                encoded[i+4] == 0x48 && encoded[i+5] == 0x01 &&
                encoded[i+6] == 0x65 && encoded[i+7] == 0x03 &&
                encoded[i+8] == 0x04 && encoded[i+9] == 0x04) {
                return switch (encoded[i+10]) {
                    case 0x01 -> "ML-KEM-512";
                    case 0x02 -> "ML-KEM-768";
                    case 0x03 -> "ML-KEM-1024";
                    default -> "ML-KEM";
                };
            }
        }
        return detectAlgorithmFromSize(encoded.length, false);
    }

    private String detectAlgorithmFromSize(int length, boolean isPublic) {
        // ML-KEM key sizes (approximate, includes encoding overhead):
        // ML-KEM-512: public ~800 bytes, private ~1632 bytes
        // ML-KEM-768: public ~1184 bytes, private ~2400 bytes
        // ML-KEM-1024: public ~1568 bytes, private ~3168 bytes
        if (isPublic) {
            if (length < 1000) return "ML-KEM-512";
            if (length < 1400) return "ML-KEM-768";
            return "ML-KEM-1024";
        } else {
            if (length < 2000) return "ML-KEM-512";
            if (length < 2800) return "ML-KEM-768";
            return "ML-KEM-1024";
        }
    }
}
