package net.glassless.provider.internal.keyfactory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * EC (Elliptic Curve) KeyFactory implementation.
 * Supports conversion between EC keys and various key specifications.
 */
public class ECKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec x509Spec = (X509EncodedKeySpec) keySpec;
            return generatePublicKeyFromEncoded(x509Spec.getEncoded());

        } else if (keySpec instanceof ECPublicKeySpec) {
            ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
            return generatePublicKeyFromSpec(ecSpec);

        } else {
            throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            PKCS8EncodedKeySpec pkcs8Spec = (PKCS8EncodedKeySpec) keySpec;
            return generatePrivateKeyFromEncoded(pkcs8Spec.getEncoded());

        } else if (keySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
            return generatePrivateKeyFromSpec(ecSpec);

        } else {
            throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) key;

            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException("Key does not support encoding");
                }
                return (T) new X509EncodedKeySpec(encoded);

            } else if (ECPublicKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new ECPublicKeySpec(ecKey.getW(), ecKey.getParams());

            } else {
                throw new InvalidKeySpecException("Unsupported KeySpec for EC public key: " + keySpec.getName());
            }

        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey ecKey = (ECPrivateKey) key;

            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException("Key does not support encoding");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);

            } else if (ECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new ECPrivateKeySpec(ecKey.getS(), ecKey.getParams());

            } else {
                throw new InvalidKeySpecException("Unsupported KeySpec for EC private key: " + keySpec.getName());
            }

        } else {
            throw new InvalidKeySpecException("Key is not an EC key");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key instanceof ECPublicKey || key instanceof ECPrivateKey) {
            // Already an EC key, return as-is or re-encode
            try {
                if (key instanceof PublicKey) {
                    byte[] encoded = key.getEncoded();
                    if (encoded != null) {
                        return generatePublicKeyFromEncoded(encoded);
                    }
                } else {
                    byte[] encoded = key.getEncoded();
                    if (encoded != null) {
                        return generatePrivateKeyFromEncoded(encoded);
                    }
                }
                return key;
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Cannot translate key", e);
            }
        }

        throw new InvalidKeyException("Key is not an EC key");
    }

    private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to decode EC public key", e);
        }
    }

    private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to decode EC private key", e);
        }
    }

    private PublicKey generatePublicKeyFromSpec(ECPublicKeySpec spec) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to generate EC public key from spec", e);
        }
    }

    private PrivateKey generatePrivateKeyFromSpec(ECPrivateKeySpec spec) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to generate EC private key from spec", e);
        }
    }
}
