package net.glassless.provider.internal.keyfactory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * RSA KeyFactory implementation using OpenSSL.
 * Supports conversion between RSA keys and various key specifications.
 */
public class RSAKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec x509Spec = (X509EncodedKeySpec) keySpec;
            return generatePublicKeyFromEncoded(x509Spec.getEncoded());

        } else if (keySpec instanceof RSAPublicKeySpec) {
            RSAPublicKeySpec rsaSpec = (RSAPublicKeySpec) keySpec;
            return generatePublicKeyFromSpec(rsaSpec);

        } else {
            throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            PKCS8EncodedKeySpec pkcs8Spec = (PKCS8EncodedKeySpec) keySpec;
            return generatePrivateKeyFromEncoded(pkcs8Spec.getEncoded());

        } else if (keySpec instanceof RSAPrivateCrtKeySpec) {
            RSAPrivateCrtKeySpec rsaCrtSpec = (RSAPrivateCrtKeySpec) keySpec;
            return generatePrivateKeyFromCrtSpec(rsaCrtSpec);

        } else if (keySpec instanceof RSAPrivateKeySpec) {
            RSAPrivateKeySpec rsaSpec = (RSAPrivateKeySpec) keySpec;
            return generatePrivateKeyFromSpec(rsaSpec);

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

        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) key;

            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException("Key does not support encoding");
                }
                return (T) new X509EncodedKeySpec(encoded);

            } else if (RSAPublicKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());

            } else {
                throw new InvalidKeySpecException("Unsupported KeySpec for RSA public key: " + keySpec.getName());
            }

        } else if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaCrtKey = (RSAPrivateCrtKey) key;

            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException("Key does not support encoding");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);

            } else if (RSAPrivateCrtKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new RSAPrivateCrtKeySpec(
                    rsaCrtKey.getModulus(),
                    rsaCrtKey.getPublicExponent(),
                    rsaCrtKey.getPrivateExponent(),
                    rsaCrtKey.getPrimeP(),
                    rsaCrtKey.getPrimeQ(),
                    rsaCrtKey.getPrimeExponentP(),
                    rsaCrtKey.getPrimeExponentQ(),
                    rsaCrtKey.getCrtCoefficient()
                );

            } else if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new RSAPrivateKeySpec(rsaCrtKey.getModulus(), rsaCrtKey.getPrivateExponent());

            } else {
                throw new InvalidKeySpecException("Unsupported KeySpec for RSA private CRT key: " + keySpec.getName());
            }

        } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsaKey = (RSAPrivateKey) key;

            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException("Key does not support encoding");
                }
                return (T) new PKCS8EncodedKeySpec(encoded);

            } else if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                return (T) new RSAPrivateKeySpec(rsaKey.getModulus(), rsaKey.getPrivateExponent());

            } else {
                throw new InvalidKeySpecException("Unsupported KeySpec for RSA private key: " + keySpec.getName());
            }

        } else {
            throw new InvalidKeySpecException("Key is not an RSA key");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (key instanceof RSAPublicKey || key instanceof RSAPrivateKey) {
            // Already an RSA key, return as-is or re-encode
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

        throw new InvalidKeyException("Key is not an RSA key");
    }

    private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try {
            // Use Java's built-in KeyFactory to parse the encoded key
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to decode RSA public key", e);
        }
    }

    private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
        try {
            // Use Java's built-in KeyFactory to parse the encoded key
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to decode RSA private key", e);
        }
    }

    private PublicKey generatePublicKeyFromSpec(RSAPublicKeySpec spec) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to generate RSA public key from spec", e);
        }
    }

    private PrivateKey generatePrivateKeyFromSpec(RSAPrivateKeySpec spec) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to generate RSA private key from spec", e);
        }
    }

    private PrivateKey generatePrivateKeyFromCrtSpec(RSAPrivateCrtKeySpec spec) throws InvalidKeySpecException {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Failed to generate RSA private CRT key from spec", e);
        }
    }
}
