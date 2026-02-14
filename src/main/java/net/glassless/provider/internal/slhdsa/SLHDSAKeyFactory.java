package net.glassless.provider.internal.slhdsa;

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
 * KeyFactory for SLH-DSA keys.
 * Supports all 12 SLH-DSA variants.
 */
public class SLHDSAKeyFactory extends KeyFactorySpi {

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
        if (key instanceof GlaSSLessSLHDSAPublicKey pubKey) {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new X509EncodedKeySpec(pubKey.getEncoded());
            }
        } else if (key instanceof GlaSSLessSLHDSAPrivateKey privKey) {
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
        if (key instanceof GlaSSLessSLHDSAPublicKey || key instanceof GlaSSLessSLHDSAPrivateKey) {
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
            if (pkey == null || pkey.address() == 0) {
                throw new InvalidKeySpecException("Failed to parse SLH-DSA public key");
            }

            try {
                String algorithm = detectAlgorithm(encoded);
                return new GlaSSLessSLHDSAPublicKey(algorithm, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate SLH-DSA public key", e);
        }
    }

    private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
            if (pkey == null || pkey.address() == 0) {
                throw new InvalidKeySpecException("Failed to parse SLH-DSA private key");
            }

            try {
                String algorithm = detectAlgorithm(encoded);
                return new GlaSSLessSLHDSAPrivateKey(algorithm, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate SLH-DSA private key", e);
        }
    }

    /**
     * Detects the SLH-DSA variant from the encoded key based on OID.
     * SLH-DSA OIDs are defined in FIPS 205 under 2.16.840.1.101.3.4.3.
     */
    private String detectAlgorithm(byte[] encoded) {
        // SLH-DSA OIDs: 2.16.840.1.101.3.4.3.{20-31}
        // Base OID encoding: 60 86 48 01 65 03 04 03
        // Look for the base OID followed by the variant identifier
        byte[] baseOid = {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03};

        for (int i = 0; i < encoded.length - baseOid.length - 1; i++) {
            boolean match = true;
            for (int j = 0; j < baseOid.length; j++) {
                if (encoded[i + j] != baseOid[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                int variantByte = encoded[i + baseOid.length] & 0xFF;
                return switch (variantByte) {
                    case 0x14 -> "SLH-DSA-SHA2-128s";  // 20
                    case 0x15 -> "SLH-DSA-SHA2-128f";  // 21
                    case 0x16 -> "SLH-DSA-SHA2-192s";  // 22
                    case 0x17 -> "SLH-DSA-SHA2-192f";  // 23
                    case 0x18 -> "SLH-DSA-SHA2-256s";  // 24
                    case 0x19 -> "SLH-DSA-SHA2-256f";  // 25
                    case 0x1A -> "SLH-DSA-SHAKE-128s"; // 26
                    case 0x1B -> "SLH-DSA-SHAKE-128f"; // 27
                    case 0x1C -> "SLH-DSA-SHAKE-192s"; // 28
                    case 0x1D -> "SLH-DSA-SHAKE-192f"; // 29
                    case 0x1E -> "SLH-DSA-SHAKE-256s"; // 30
                    case 0x1F -> "SLH-DSA-SHAKE-256f"; // 31
                    default -> "SLH-DSA";
                };
            }
        }
        return "SLH-DSA";
    }
}
