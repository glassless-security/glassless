package net.glassless.provider.internal.signature;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for signature implementations using OpenSSL EVP_DigestSign/Verify API.
 */
public abstract class AbstractSignature extends SignatureSpi {

    private final String digestAlgorithm;
    private final KeyType keyType;

    private int mdCtx;
    private int evpPkey;
    private int pkeyCtxPtr;
    private boolean signing;
    private ByteArrayOutputStream dataBuffer;

    protected AbstractSignature(String digestAlgorithm, KeyType keyType) {
        this.digestAlgorithm = digestAlgorithm;
        this.keyType = keyType;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        this.signing = false;

        try {
            byte[] keyBytes = publicKey.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key encoding not available");
            }

            evpPkey = OpenSSLCrypto.loadPublicKey(keyBytes);
            if (evpPkey == 0) {
                throw new InvalidKeyException("Failed to load public key");
            }

            initVerify();

        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error initializing signature verification", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        reset();
        this.signing = true;

        try {
            byte[] keyBytes = privateKey.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key encoding not available");
            }

            // Use type 0 for auto-detection
            evpPkey = OpenSSLCrypto.loadPrivateKey(0, keyBytes);
            if (evpPkey == 0) {
                throw new InvalidKeyException("Failed to load private key");
            }

            initSign();

        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error initializing signature", e);
        }
    }

    private void initSign() throws Throwable {
        mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
        if (mdCtx == 0) {
            throw new ProviderException("Failed to create EVP_MD_CTX");
        }

        int digestHandle = OpenSSLCrypto.getDigestHandle(digestAlgorithm);
        if (digestHandle == 0) {
            throw new ProviderException("Unknown digest algorithm: " + digestAlgorithm);
        }

        // Allocate pointer for EVP_PKEY_CTX (output parameter) - wasm32 pointer is 4 bytes
        pkeyCtxPtr = OpenSSLCrypto.malloc(4);

        int result = OpenSSLCrypto.EVP_DigestSignInit(mdCtx, pkeyCtxPtr, digestHandle, 0, evpPkey);
        if (result != 1) {
            throw new ProviderException("EVP_DigestSignInit failed");
        }

        // Get the actual EVP_PKEY_CTX for configuring padding etc.
        int pkeyCtx = OpenSSLCrypto.memory().readInt(pkeyCtxPtr);

        // Configure algorithm-specific parameters
        configureContext(pkeyCtx);

        dataBuffer = new ByteArrayOutputStream();
    }

    private void initVerify() throws Throwable {
        mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
        if (mdCtx == 0) {
            throw new ProviderException("Failed to create EVP_MD_CTX");
        }

        int digestHandle = OpenSSLCrypto.getDigestHandle(digestAlgorithm);
        if (digestHandle == 0) {
            throw new ProviderException("Unknown digest algorithm: " + digestAlgorithm);
        }

        // Allocate pointer for EVP_PKEY_CTX (output parameter) - wasm32 pointer is 4 bytes
        pkeyCtxPtr = OpenSSLCrypto.malloc(4);

        int result = OpenSSLCrypto.EVP_DigestVerifyInit(mdCtx, pkeyCtxPtr, digestHandle, 0, evpPkey);
        if (result != 1) {
            throw new ProviderException("EVP_DigestVerifyInit failed");
        }

        // Get the actual EVP_PKEY_CTX for configuring padding etc.
        int pkeyCtx = OpenSSLCrypto.memory().readInt(pkeyCtxPtr);

        // Configure algorithm-specific parameters
        configureContext(pkeyCtx);

        dataBuffer = new ByteArrayOutputStream();
    }

    /**
     * Configure algorithm-specific parameters on the EVP_PKEY_CTX.
     * Subclasses can override to set padding, salt length, etc.
     */
    protected void configureContext(int pkeyCtx) throws Throwable {
        // Default: no additional configuration
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (dataBuffer == null) {
            throw new SignatureException("Signature not initialized");
        }
        dataBuffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (dataBuffer == null) {
            throw new SignatureException("Signature not initialized");
        }
        dataBuffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!signing || mdCtx == 0) {
            throw new SignatureException("Signature not initialized for signing");
        }

        int dataPtr = 0;
        int sigLenPtr = 0;
        int sigPtr = 0;

        try {
            // Update with buffered data
            byte[] data = dataBuffer.toByteArray();
            if (data.length > 0) {
                dataPtr = OpenSSLCrypto.malloc(data.length);
                OpenSSLCrypto.memory().write(dataPtr, data);
                int result = OpenSSLCrypto.EVP_DigestSignUpdate(mdCtx, dataPtr, data.length);
                if (result != 1) {
                    throw new SignatureException("EVP_DigestSignUpdate failed");
                }
            }

            // Get signature length first (size_t is 4 bytes in wasm32)
            sigLenPtr = OpenSSLCrypto.malloc(4);
            int result = OpenSSLCrypto.EVP_DigestSignFinal(mdCtx, 0, sigLenPtr);
            if (result != 1) {
                throw new SignatureException("EVP_DigestSignFinal failed (size query)");
            }

            int sigLen = OpenSSLCrypto.memory().readInt(sigLenPtr);
            sigPtr = OpenSSLCrypto.malloc(sigLen);

            // Get actual signature
            result = OpenSSLCrypto.EVP_DigestSignFinal(mdCtx, sigPtr, sigLenPtr);
            if (result != 1) {
                throw new SignatureException("EVP_DigestSignFinal failed");
            }

            sigLen = OpenSSLCrypto.memory().readInt(sigLenPtr);
            byte[] signature = OpenSSLCrypto.memory().readBytes(sigPtr, sigLen);

            return signature;

        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error signing data", e);
        } finally {
            OpenSSLCrypto.free(dataPtr);
            OpenSSLCrypto.free(sigLenPtr);
            OpenSSLCrypto.free(sigPtr);
            reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (signing || mdCtx == 0) {
            throw new SignatureException("Signature not initialized for verification");
        }

        int dataPtr = 0;
        int sigPtr = 0;

        try {
            // Update with buffered data
            byte[] data = dataBuffer.toByteArray();
            if (data.length > 0) {
                dataPtr = OpenSSLCrypto.malloc(data.length);
                OpenSSLCrypto.memory().write(dataPtr, data);
                int result = OpenSSLCrypto.EVP_DigestVerifyUpdate(mdCtx, dataPtr, data.length);
                if (result != 1) {
                    throw new SignatureException("EVP_DigestVerifyUpdate failed");
                }
            }

            // Verify signature
            sigPtr = OpenSSLCrypto.malloc(sigBytes.length);
            OpenSSLCrypto.memory().write(sigPtr, sigBytes);

            int result = OpenSSLCrypto.EVP_DigestVerifyFinal(mdCtx, sigPtr, sigBytes.length);

            // result == 1 means success, 0 means verification failed, < 0 means error
            return result == 1;

        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error verifying signature", e);
        } finally {
            OpenSSLCrypto.free(dataPtr);
            OpenSSLCrypto.free(sigPtr);
            reset();
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    private void reset() {
        if (mdCtx != 0) {
            try {
                OpenSSLCrypto.EVP_MD_CTX_free(mdCtx);
            } catch (Throwable e) {
                // Ignore
            }
            mdCtx = 0;
        }
        if (evpPkey != 0) {
            try {
                OpenSSLCrypto.EVP_PKEY_free(evpPkey);
            } catch (Throwable e) {
                // Ignore
            }
            evpPkey = 0;
        }
        if (pkeyCtxPtr != 0) {
            OpenSSLCrypto.free(pkeyCtxPtr);
            pkeyCtxPtr = 0;
        }
        dataBuffer = null;
    }

    /**
     * Key type for the signature algorithm.
     */
    public enum KeyType {
        RSA,
        EC,
        RSA_PSS,
        DSA
    }
}
