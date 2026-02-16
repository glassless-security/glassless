package net.glassless.provider.internal.eddsa;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyFactory for EdDSA keys (Ed25519 and Ed448).
 */
public class EdDSAKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec x509Spec) {
            return generatePublicFromEncoded(x509Spec.getEncoded());
        } else if (keySpec instanceof EdECPublicKeySpec edSpec) {
            return generatePublicFromSpec(edSpec);
        } else {
            throw new InvalidKeySpecException("Unsupported key spec: " +
                (keySpec == null ? "null" : keySpec.getClass().getName()));
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
            return generatePrivateFromEncoded(pkcs8Spec.getEncoded());
        } else if (keySpec instanceof EdECPrivateKeySpec edSpec) {
            return generatePrivateFromSpec(edSpec);
        } else {
            throw new InvalidKeySpecException("Unsupported key spec: " +
                (keySpec == null ? "null" : keySpec.getClass().getName()));
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key instanceof EdECPublicKey pubKey) {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new X509EncodedKeySpec(pubKey.getEncoded());
            } else if (EdECPublicKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new EdECPublicKeySpec(pubKey.getParams(), pubKey.getPoint());
            }
        } else if (key instanceof EdECPrivateKey privKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new PKCS8EncodedKeySpec(privKey.getEncoded());
            } else if (EdECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                if (privKey.getBytes().isPresent()) {
                    return (T) new EdECPrivateKeySpec(privKey.getParams(), privKey.getBytes().get());
                }
            }
        }
        throw new InvalidKeySpecException("Unsupported key type or spec: " +
            (key == null ? "null" : key.getClass().getName()) + " / " +
            (keySpec == null ? "null" : keySpec.getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof GlaSSLessEdECPublicKey || key instanceof GlaSSLessEdECPrivateKey) {
            return key;  // Already our implementation
        }

        if (key instanceof EdECPublicKey pubKey) {
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(pubKey.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Failed to translate public key", e);
            }
        } else if (key instanceof EdECPrivateKey privKey) {
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
            // Load the key with OpenSSL to validate and extract info
            MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
            if (pkey.equals(MemorySegment.NULL)) {
                throw new InvalidKeySpecException("Failed to parse EdDSA public key");
            }

            try {
                // Determine the curve from the encoded key
                NamedParameterSpec params = detectCurveFromPublicKey(encoded);

                // Extract raw public key
                int keyLen = params.getName().equalsIgnoreCase("Ed25519") ? 32 : 57;
                byte[] rawKey = new byte[keyLen];
                System.arraycopy(encoded, encoded.length - keyLen, rawKey, 0, keyLen);

                // Create EdECPoint
                EdECPoint point = createEdECPoint(rawKey);

                return new GlaSSLessEdECPublicKey(params, point, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate EdDSA public key", e);
        }
    }

    private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try (Arena arena = Arena.ofConfined()) {
            // Load the key with OpenSSL to validate
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
            if (pkey.equals(MemorySegment.NULL)) {
                throw new InvalidKeySpecException("Failed to parse EdDSA private key");
            }

            try {
                // Determine the curve from the encoded key
                NamedParameterSpec params = detectCurveFromPrivateKey(encoded);

                // Extract raw private key
                int keyLen = params.getName().equalsIgnoreCase("Ed25519") ? 32 : 57;
                byte[] rawKey = new byte[keyLen];
                System.arraycopy(encoded, encoded.length - keyLen, rawKey, 0, keyLen);

                return new GlaSSLessEdECPrivateKey(params, rawKey, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate EdDSA private key", e);
        }
    }

    private PublicKey generatePublicFromSpec(EdECPublicKeySpec spec) throws InvalidKeySpecException {
        // Convert spec to encoded form
        NamedParameterSpec params = spec.getParams();
        EdECPoint point = spec.getPoint();

        // Encode the point to raw bytes
        byte[] rawKey = encodeEdECPoint(point, params);

        // Create X.509 encoded form
        byte[] encoded = createX509Encoding(params, rawKey);

        return new GlaSSLessEdECPublicKey(params, point, encoded);
    }

    private PrivateKey generatePrivateFromSpec(EdECPrivateKeySpec spec) throws InvalidKeySpecException {
        NamedParameterSpec params = spec.getParams();
        byte[] keyBytes = spec.getBytes();

        // Create PKCS#8 encoded form
        byte[] encoded = createPKCS8Encoding(params, keyBytes);

        return new GlaSSLessEdECPrivateKey(params, keyBytes, encoded);
    }

    private NamedParameterSpec detectCurveFromPublicKey(byte[] encoded) {
        // Ed25519 X.509 encoded is 44 bytes, Ed448 is 69 bytes
        if (encoded.length == 44) {
            return NamedParameterSpec.ED25519;
        } else if (encoded.length == 69) {
            return NamedParameterSpec.ED448;
        }
        // Check OID in the AlgorithmIdentifier
        // Ed25519 OID: 1.3.101.112 (06 03 2B 65 70)
        // Ed448 OID: 1.3.101.113 (06 03 2B 65 71)
        for (int i = 0; i < encoded.length - 4; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x03 &&
                encoded[i+2] == 0x2B && encoded[i+3] == 0x65) {
                if (encoded[i+4] == 0x70) return NamedParameterSpec.ED25519;
                if (encoded[i+4] == 0x71) return NamedParameterSpec.ED448;
            }
        }
        throw new ProviderException("Unable to detect EdDSA curve from encoded key");
    }

    private NamedParameterSpec detectCurveFromPrivateKey(byte[] encoded) {
        // Ed25519 PKCS#8 encoded is 48 bytes, Ed448 is 73 bytes
        if (encoded.length == 48) {
            return NamedParameterSpec.ED25519;
        } else if (encoded.length == 73) {
            return NamedParameterSpec.ED448;
        }
        // Check OID in the AlgorithmIdentifier
        for (int i = 0; i < encoded.length - 4; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x03 &&
                encoded[i+2] == 0x2B && encoded[i+3] == 0x65) {
                if (encoded[i+4] == 0x70) return NamedParameterSpec.ED25519;
                if (encoded[i+4] == 0x71) return NamedParameterSpec.ED448;
            }
        }
        throw new ProviderException("Unable to detect EdDSA curve from encoded key");
    }

    private EdECPoint createEdECPoint(byte[] raw) {
        // EdDSA encodes the point as: y-coordinate with x sign in MSB (little-endian)
        byte[] reversed = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) {
            reversed[i] = raw[raw.length - 1 - i];
        }

        boolean xOdd = (reversed[0] & 0x80) != 0;
        reversed[0] &= 0x7F;

        BigInteger y = new BigInteger(1, reversed);
        return new EdECPoint(xOdd, y);
    }

    private byte[] encodeEdECPoint(EdECPoint point, NamedParameterSpec params) {
        int keyLen = params.getName().equalsIgnoreCase("Ed25519") ? 32 : 57;

        // Get y-coordinate bytes (big-endian)
        byte[] yBytes = point.getY().toByteArray();

        // Convert to little-endian and fit to key length
        byte[] raw = new byte[keyLen];
        int srcOffset = yBytes[0] == 0 ? 1 : 0;  // Skip leading zero if present
        int srcLen = yBytes.length - srcOffset;
        int dstOffset = 0;

        // Reverse into raw (little-endian)
        for (int i = 0; i < srcLen && i < keyLen; i++) {
            raw[i] = yBytes[yBytes.length - 1 - i];
        }

        // Set the x sign bit in the last byte
        if (point.isXOdd()) {
            raw[keyLen - 1] |= 0x80;
        }

        return raw;
    }

    private byte[] createX509Encoding(NamedParameterSpec params, byte[] rawKey) {
        // Build SubjectPublicKeyInfo structure
        byte[] oid;
        if (params.getName().equalsIgnoreCase("Ed25519")) {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x70 };  // 1.3.101.112
        } else {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x71 };  // 1.3.101.113
        }

        // AlgorithmIdentifier: SEQUENCE { OID }
        byte[] algId = new byte[2 + oid.length];
        algId[0] = 0x30;  // SEQUENCE
        algId[1] = (byte) oid.length;
        System.arraycopy(oid, 0, algId, 2, oid.length);

        // BIT STRING { raw key }
        byte[] bitString = new byte[2 + 1 + rawKey.length];
        bitString[0] = 0x03;  // BIT STRING
        bitString[1] = (byte) (1 + rawKey.length);
        bitString[2] = 0x00;  // unused bits
        System.arraycopy(rawKey, 0, bitString, 3, rawKey.length);

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        int totalLen = algId.length + bitString.length;
        byte[] encoded = new byte[2 + totalLen];
        encoded[0] = 0x30;  // SEQUENCE
        encoded[1] = (byte) totalLen;
        System.arraycopy(algId, 0, encoded, 2, algId.length);
        System.arraycopy(bitString, 0, encoded, 2 + algId.length, bitString.length);

        return encoded;
    }

    private byte[] createPKCS8Encoding(NamedParameterSpec params, byte[] keyBytes) {
        // Build PrivateKeyInfo structure
        byte[] oid;
        if (params.getName().equalsIgnoreCase("Ed25519")) {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x70 };  // 1.3.101.112
        } else {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x71 };  // 1.3.101.113
        }

        // Version: INTEGER 0
        byte[] version = new byte[] { 0x02, 0x01, 0x00 };

        // AlgorithmIdentifier: SEQUENCE { OID }
        byte[] algId = new byte[2 + oid.length];
        algId[0] = 0x30;  // SEQUENCE
        algId[1] = (byte) oid.length;
        System.arraycopy(oid, 0, algId, 2, oid.length);

        // Private key: OCTET STRING { OCTET STRING { key bytes } }
        byte[] innerOctet = new byte[2 + keyBytes.length];
        innerOctet[0] = 0x04;  // OCTET STRING
        innerOctet[1] = (byte) keyBytes.length;
        System.arraycopy(keyBytes, 0, innerOctet, 2, keyBytes.length);

        byte[] outerOctet = new byte[2 + innerOctet.length];
        outerOctet[0] = 0x04;  // OCTET STRING
        outerOctet[1] = (byte) innerOctet.length;
        System.arraycopy(innerOctet, 0, outerOctet, 2, innerOctet.length);

        // PrivateKeyInfo: SEQUENCE { version, algorithmIdentifier, privateKey }
        int totalLen = version.length + algId.length + outerOctet.length;
        byte[] encoded = new byte[2 + totalLen];
        encoded[0] = 0x30;  // SEQUENCE
        encoded[1] = (byte) totalLen;
        int offset = 2;
        System.arraycopy(version, 0, encoded, offset, version.length);
        offset += version.length;
        System.arraycopy(algId, 0, encoded, offset, algId.length);
        offset += algId.length;
        System.arraycopy(outerOctet, 0, encoded, offset, outerOctet.length);

        return encoded;
    }
}
