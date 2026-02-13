package net.glassless.provider.internal.xdh;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyFactory for XDH keys (X25519 and X448).
 */
public class XDHKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec x509Spec) {
            return generatePublicFromEncoded(x509Spec.getEncoded());
        } else if (keySpec instanceof XECPublicKeySpec xecSpec) {
            return generatePublicFromSpec(xecSpec);
        } else {
            throw new InvalidKeySpecException("Unsupported key spec: " +
                (keySpec == null ? "null" : keySpec.getClass().getName()));
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
            return generatePrivateFromEncoded(pkcs8Spec.getEncoded());
        } else if (keySpec instanceof XECPrivateKeySpec xecSpec) {
            return generatePrivateFromSpec(xecSpec);
        } else {
            throw new InvalidKeySpecException("Unsupported key spec: " +
                (keySpec == null ? "null" : keySpec.getClass().getName()));
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key instanceof XECPublicKey pubKey) {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new X509EncodedKeySpec(pubKey.getEncoded());
            } else if (XECPublicKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new XECPublicKeySpec(pubKey.getParams(), pubKey.getU());
            }
        } else if (key instanceof XECPrivateKey privKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new PKCS8EncodedKeySpec(privKey.getEncoded());
            } else if (XECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                if (privKey.getScalar().isPresent()) {
                    return (T) new XECPrivateKeySpec(privKey.getParams(), privKey.getScalar().get());
                }
            }
        }
        throw new InvalidKeySpecException("Unsupported key type or spec: " +
            (key == null ? "null" : key.getClass().getName()) + " / " +
            (keySpec == null ? "null" : keySpec.getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof GlasslessXECPublicKey || key instanceof GlasslessXECPrivateKey) {
            return key;
        }

        if (key instanceof XECPublicKey pubKey) {
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(pubKey.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Failed to translate public key", e);
            }
        } else if (key instanceof XECPrivateKey privKey) {
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
                throw new InvalidKeySpecException("Failed to parse XDH public key");
            }

            try {
                NamedParameterSpec params = detectCurveFromPublicKey(encoded);
                int keyLen = params.getName().equalsIgnoreCase("X25519") ? 32 : 56;

                byte[] rawKey = new byte[keyLen];
                System.arraycopy(encoded, encoded.length - keyLen, rawKey, 0, keyLen);

                BigInteger u = createUCoordinate(rawKey);

                return new GlasslessXECPublicKey(params, u, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate XDH public key", e);
        }
    }

    private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
            if (pkey == null || pkey.address() == 0) {
                throw new InvalidKeySpecException("Failed to parse XDH private key");
            }

            try {
                NamedParameterSpec params = detectCurveFromPrivateKey(encoded);
                int keyLen = params.getName().equalsIgnoreCase("X25519") ? 32 : 56;

                byte[] rawKey = new byte[keyLen];
                System.arraycopy(encoded, encoded.length - keyLen, rawKey, 0, keyLen);

                return new GlasslessXECPrivateKey(params, rawKey, encoded);
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (Throwable e) {
            throw new InvalidKeySpecException("Failed to generate XDH private key", e);
        }
    }

    private PublicKey generatePublicFromSpec(XECPublicKeySpec spec) throws InvalidKeySpecException {
        if (!(spec.getParams() instanceof NamedParameterSpec params)) {
            throw new InvalidKeySpecException("NamedParameterSpec required");
        }

        BigInteger u = spec.getU();
        byte[] rawKey = encodeUCoordinate(u, params);
        byte[] encoded = createX509Encoding(params, rawKey);

        return new GlasslessXECPublicKey(params, u, encoded);
    }

    private PrivateKey generatePrivateFromSpec(XECPrivateKeySpec spec) throws InvalidKeySpecException {
        if (!(spec.getParams() instanceof NamedParameterSpec params)) {
            throw new InvalidKeySpecException("NamedParameterSpec required");
        }

        byte[] scalar = spec.getScalar();
        byte[] encoded = createPKCS8Encoding(params, scalar);

        return new GlasslessXECPrivateKey(params, scalar, encoded);
    }

    private NamedParameterSpec detectCurveFromPublicKey(byte[] encoded) {
        // X25519 X.509 encoded is 44 bytes, X448 is 68 bytes
        if (encoded.length == 44) {
            return NamedParameterSpec.X25519;
        } else if (encoded.length == 68) {
            return NamedParameterSpec.X448;
        }
        // Check OID: X25519 OID: 1.3.101.110 (06 03 2B 65 6E), X448 OID: 1.3.101.111 (06 03 2B 65 6F)
        for (int i = 0; i < encoded.length - 4; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x03 &&
                encoded[i+2] == 0x2B && encoded[i+3] == 0x65) {
                if (encoded[i+4] == 0x6E) return NamedParameterSpec.X25519;
                if (encoded[i+4] == 0x6F) return NamedParameterSpec.X448;
            }
        }
        throw new ProviderException("Unable to detect XDH curve from encoded key");
    }

    private NamedParameterSpec detectCurveFromPrivateKey(byte[] encoded) {
        // X25519 PKCS#8 encoded is 48 bytes, X448 is 72 bytes
        if (encoded.length == 48) {
            return NamedParameterSpec.X25519;
        } else if (encoded.length == 72) {
            return NamedParameterSpec.X448;
        }
        // Check OID
        for (int i = 0; i < encoded.length - 4; i++) {
            if (encoded[i] == 0x06 && encoded[i+1] == 0x03 &&
                encoded[i+2] == 0x2B && encoded[i+3] == 0x65) {
                if (encoded[i+4] == 0x6E) return NamedParameterSpec.X25519;
                if (encoded[i+4] == 0x6F) return NamedParameterSpec.X448;
            }
        }
        throw new ProviderException("Unable to detect XDH curve from encoded key");
    }

    private BigInteger createUCoordinate(byte[] raw) {
        // XDH uses little-endian encoding
        byte[] reversed = new byte[raw.length + 1];
        reversed[0] = 0;  // Ensure positive
        for (int i = 0; i < raw.length; i++) {
            reversed[i + 1] = raw[raw.length - 1 - i];
        }
        return new BigInteger(reversed);
    }

    private byte[] encodeUCoordinate(BigInteger u, NamedParameterSpec params) {
        int keyLen = params.getName().equalsIgnoreCase("X25519") ? 32 : 56;
        byte[] uBytes = u.toByteArray();

        // Convert to little-endian and fit to key length
        byte[] raw = new byte[keyLen];
        int srcOffset = uBytes[0] == 0 ? 1 : 0;
        int srcLen = uBytes.length - srcOffset;

        // Reverse into raw (little-endian)
        for (int i = 0; i < srcLen && i < keyLen; i++) {
            raw[i] = uBytes[uBytes.length - 1 - i];
        }

        return raw;
    }

    private byte[] createX509Encoding(NamedParameterSpec params, byte[] rawKey) {
        byte[] oid;
        if (params.getName().equalsIgnoreCase("X25519")) {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x6E };  // 1.3.101.110
        } else {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x6F };  // 1.3.101.111
        }

        // AlgorithmIdentifier: SEQUENCE { OID }
        byte[] algId = new byte[2 + oid.length];
        algId[0] = 0x30;
        algId[1] = (byte) oid.length;
        System.arraycopy(oid, 0, algId, 2, oid.length);

        // BIT STRING { raw key }
        byte[] bitString = new byte[2 + 1 + rawKey.length];
        bitString[0] = 0x03;
        bitString[1] = (byte) (1 + rawKey.length);
        bitString[2] = 0x00;
        System.arraycopy(rawKey, 0, bitString, 3, rawKey.length);

        // SubjectPublicKeyInfo: SEQUENCE
        int totalLen = algId.length + bitString.length;
        byte[] encoded = new byte[2 + totalLen];
        encoded[0] = 0x30;
        encoded[1] = (byte) totalLen;
        System.arraycopy(algId, 0, encoded, 2, algId.length);
        System.arraycopy(bitString, 0, encoded, 2 + algId.length, bitString.length);

        return encoded;
    }

    private byte[] createPKCS8Encoding(NamedParameterSpec params, byte[] keyBytes) {
        byte[] oid;
        if (params.getName().equalsIgnoreCase("X25519")) {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x6E };  // 1.3.101.110
        } else {
            oid = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x6F };  // 1.3.101.111
        }

        byte[] version = new byte[] { 0x02, 0x01, 0x00 };

        byte[] algId = new byte[2 + oid.length];
        algId[0] = 0x30;
        algId[1] = (byte) oid.length;
        System.arraycopy(oid, 0, algId, 2, oid.length);

        // Private key: OCTET STRING { OCTET STRING { key bytes } }
        byte[] innerOctet = new byte[2 + keyBytes.length];
        innerOctet[0] = 0x04;
        innerOctet[1] = (byte) keyBytes.length;
        System.arraycopy(keyBytes, 0, innerOctet, 2, keyBytes.length);

        byte[] outerOctet = new byte[2 + innerOctet.length];
        outerOctet[0] = 0x04;
        outerOctet[1] = (byte) innerOctet.length;
        System.arraycopy(innerOctet, 0, outerOctet, 2, innerOctet.length);

        int totalLen = version.length + algId.length + outerOctet.length;
        byte[] encoded = new byte[2 + totalLen];
        encoded[0] = 0x30;
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
