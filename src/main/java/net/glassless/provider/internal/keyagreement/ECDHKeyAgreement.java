package net.glassless.provider.internal.keyagreement;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * ECDH (Elliptic Curve Diffie-Hellman) key agreement using OpenSSL.
 */
public class ECDHKeyAgreement extends KeyAgreementSpi {

    private ECPrivateKey privateKey;
    private ECPublicKey peerPublicKey;
    private byte[] sharedSecret;

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof ECPrivateKey)) {
            throw new InvalidKeyException("ECDH requires an ECPrivateKey");
        }
        this.privateKey = (ECPrivateKey) key;
        this.peerPublicKey = null;
        this.sharedSecret = null;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters expected for ECDH");
        }
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (privateKey == null) {
            throw new IllegalStateException("Key agreement not initialized");
        }

        if (!lastPhase) {
            throw new IllegalStateException("ECDH only supports two-party key agreement (lastPhase must be true)");
        }

        if (!(key instanceof ECPublicKey)) {
            throw new InvalidKeyException("ECDH requires an ECPublicKey for the peer");
        }

        this.peerPublicKey = (ECPublicKey) key;

        // Derive the shared secret
        try {
            deriveSharedSecret();
        } catch (Throwable e) {
            throw new InvalidKeyException("Failed to derive shared secret", e);
        }

        // ECDH does not produce an intermediate key, return null
        return null;
    }

    private void deriveSharedSecret() throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            // Load the private key
            byte[] privateKeyBytes = privateKey.getEncoded();
            MemorySegment privKey = OpenSSLCrypto.loadPrivateKey(0, privateKeyBytes, arena);
            if (privKey == null || privKey.address() == 0) {
                throw new ProviderException("Failed to load private key");
            }

            try {
                // Load the peer's public key
                byte[] publicKeyBytes = peerPublicKey.getEncoded();
                MemorySegment pubKey = OpenSSLCrypto.loadPublicKey(publicKeyBytes, arena);
                if (pubKey == null || pubKey.address() == 0) {
                    throw new ProviderException("Failed to load peer public key");
                }

                try {
                    // Derive the shared secret
                    this.sharedSecret = OpenSSLCrypto.deriveSharedSecret(privKey, pubKey, arena);
                } finally {
                    OpenSSLCrypto.EVP_PKEY_free(pubKey);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(privKey);
            }
        }
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (sharedSecret == null) {
            throw new IllegalStateException("Key agreement not completed - call doPhase first");
        }

        byte[] result = sharedSecret.clone();
        // Reset for potential reuse
        this.sharedSecret = null;
        this.peerPublicKey = null;
        return result;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (this.sharedSecret == null) {
            throw new IllegalStateException("Key agreement not completed - call doPhase first");
        }

        if (offset + this.sharedSecret.length > sharedSecret.length) {
            throw new ShortBufferException("Output buffer too small");
        }

        System.arraycopy(this.sharedSecret, 0, sharedSecret, offset, this.sharedSecret.length);
        int len = this.sharedSecret.length;

        // Reset for potential reuse
        this.sharedSecret = null;
        this.peerPublicKey = null;

        return len;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (sharedSecret == null) {
            throw new IllegalStateException("Key agreement not completed - call doPhase first");
        }

        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }

        byte[] secret = sharedSecret.clone();
        // Reset for potential reuse
        this.sharedSecret = null;
        this.peerPublicKey = null;

        return new SecretKeySpec(secret, algorithm);
    }
}
