package net.glassless.provider.internal.xdh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * XDH Key Agreement implementation (X25519 and X448) using OpenSSL.
 */
public class XDHKeyAgreement extends KeyAgreementSpi {

    private final String expectedCurve;  // null means accept any XDH curve
    private NamedParameterSpec params;
    private byte[] privateKeyEncoded;
    private byte[] sharedSecret;

    public XDHKeyAgreement() {
        this(null);
    }

    protected XDHKeyAgreement(String expectedCurve) {
        this.expectedCurve = expectedCurve;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof XECPrivateKey xecKey)) {
            throw new InvalidKeyException("XECPrivateKey required, got: " +
                (key == null ? "null" : key.getClass().getName()));
        }

        AlgorithmParameterSpec keyParams = xecKey.getParams();
        if (!(keyParams instanceof NamedParameterSpec nps)) {
            throw new InvalidKeyException("NamedParameterSpec required in key");
        }

        validateCurve(nps.getName());
        this.params = nps;
        this.privateKeyEncoded = key.getEncoded();
        this.sharedSecret = null;

        if (this.privateKeyEncoded == null) {
            throw new InvalidKeyException("Private key encoding is null");
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters expected for XDH key agreement");
        }
        engineInit(key, random);
    }

    private void validateCurve(String curveName) throws InvalidKeyException {
        if (expectedCurve != null && !expectedCurve.equalsIgnoreCase(curveName)) {
            throw new InvalidKeyException("Key curve " + curveName +
                " does not match expected curve " + expectedCurve);
        }
        if (!curveName.equalsIgnoreCase("X25519") && !curveName.equalsIgnoreCase("X448")) {
            throw new InvalidKeyException("Unsupported XDH curve: " + curveName);
        }
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (privateKeyEncoded == null) {
            throw new IllegalStateException("Key agreement not initialized");
        }

        if (!lastPhase) {
            throw new IllegalStateException("XDH key agreement requires exactly one phase");
        }

        if (!(key instanceof XECPublicKey xecKey)) {
            throw new InvalidKeyException("XECPublicKey required, got: " +
                (key == null ? "null" : key.getClass().getName()));
        }

        // Verify the public key uses the same curve
        AlgorithmParameterSpec keyParams = xecKey.getParams();
        if (keyParams instanceof NamedParameterSpec nps) {
            if (!params.getName().equalsIgnoreCase(nps.getName())) {
                throw new InvalidKeyException("Public key curve " + nps.getName() +
                    " does not match private key curve " + params.getName());
            }
        }

        byte[] publicKeyEncoded = key.getEncoded();
        if (publicKeyEncoded == null) {
            throw new InvalidKeyException("Public key encoding is null");
        }

        // Derive the shared secret
        try {
            // Load the private key
            int privateKey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded);
            if (privateKey == 0) {
                throw new InvalidKeyException("Failed to load private key");
            }

            try {
                // Load the public key
                int publicKey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded);
                if (publicKey == 0) {
                    throw new InvalidKeyException("Failed to load public key");
                }

                try {
                    // Derive the shared secret
                    this.sharedSecret = OpenSSLCrypto.deriveSharedSecret(privateKey, publicKey);
                } finally {
                    OpenSSLCrypto.EVP_PKEY_free(publicKey);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(privateKey);
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("XDH key agreement failed", e);
        }

        return null;  // XDH doesn't return intermediate keys
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (sharedSecret == null) {
            throw new IllegalStateException("No shared secret available - call doPhase first");
        }
        byte[] result = sharedSecret;
        sharedSecret = null;  // Clear after use
        return result;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException {
        byte[] secret = engineGenerateSecret();
        if (offset + secret.length > sharedSecret.length) {
            throw new IllegalStateException("Output buffer too small");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException {
        byte[] secret = engineGenerateSecret();
        return new SecretKeySpec(secret, algorithm);
    }
}
