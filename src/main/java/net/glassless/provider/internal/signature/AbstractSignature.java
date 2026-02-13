package net.glassless.provider.internal.signature;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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

    private Arena arena;
    private MemorySegment mdCtx;
    private MemorySegment evpPkey;
    private MemorySegment pkeyCtxPtr;
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
            arena = Arena.ofShared();
            byte[] keyBytes = publicKey.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key encoding not available");
            }

            evpPkey = OpenSSLCrypto.loadPublicKey(keyBytes, arena);
            if (evpPkey == null || evpPkey.address() == 0) {
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
            arena = Arena.ofShared();
            byte[] keyBytes = privateKey.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key encoding not available");
            }

            // Use type 0 for auto-detection
            evpPkey = OpenSSLCrypto.loadPrivateKey(0, keyBytes, arena);
            if (evpPkey == null || evpPkey.address() == 0) {
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
        if (mdCtx == null || mdCtx.address() == 0) {
            throw new ProviderException("Failed to create EVP_MD_CTX");
        }

        MemorySegment digestHandle = OpenSSLCrypto.getDigestHandle(digestAlgorithm, arena);
        if (digestHandle == null || digestHandle.address() == 0) {
            throw new ProviderException("Unknown digest algorithm: " + digestAlgorithm);
        }

        // Allocate pointer for EVP_PKEY_CTX (output parameter)
        pkeyCtxPtr = arena.allocate(ValueLayout.ADDRESS);

        int result = OpenSSLCrypto.EVP_DigestSignInit(mdCtx, pkeyCtxPtr, digestHandle, MemorySegment.NULL, evpPkey);
        if (result != 1) {
            throw new ProviderException("EVP_DigestSignInit failed");
        }

        // Get the actual EVP_PKEY_CTX for configuring padding etc.
        MemorySegment pkeyCtx = pkeyCtxPtr.get(ValueLayout.ADDRESS, 0);

        // Configure algorithm-specific parameters
        configureContext(pkeyCtx);

        dataBuffer = new ByteArrayOutputStream();
    }

    private void initVerify() throws Throwable {
        mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
        if (mdCtx == null || mdCtx.address() == 0) {
            throw new ProviderException("Failed to create EVP_MD_CTX");
        }

        MemorySegment digestHandle = OpenSSLCrypto.getDigestHandle(digestAlgorithm, arena);
        if (digestHandle == null || digestHandle.address() == 0) {
            throw new ProviderException("Unknown digest algorithm: " + digestAlgorithm);
        }

        // Allocate pointer for EVP_PKEY_CTX (output parameter)
        pkeyCtxPtr = arena.allocate(ValueLayout.ADDRESS);

        int result = OpenSSLCrypto.EVP_DigestVerifyInit(mdCtx, pkeyCtxPtr, digestHandle, MemorySegment.NULL, evpPkey);
        if (result != 1) {
            throw new ProviderException("EVP_DigestVerifyInit failed");
        }

        // Get the actual EVP_PKEY_CTX for configuring padding etc.
        MemorySegment pkeyCtx = pkeyCtxPtr.get(ValueLayout.ADDRESS, 0);

        // Configure algorithm-specific parameters
        configureContext(pkeyCtx);

        dataBuffer = new ByteArrayOutputStream();
    }

    /**
     * Configure algorithm-specific parameters on the EVP_PKEY_CTX.
     * Subclasses can override to set padding, salt length, etc.
     */
    protected void configureContext(MemorySegment pkeyCtx) throws Throwable {
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
        if (!signing || mdCtx == null) {
            throw new SignatureException("Signature not initialized for signing");
        }

        try (Arena confinedArena = Arena.ofConfined()) {
            // Update with buffered data
            byte[] data = dataBuffer.toByteArray();
            if (data.length > 0) {
                MemorySegment dataSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, data.length);
                dataSegment.asByteBuffer().put(data);
                int result = OpenSSLCrypto.EVP_DigestSignUpdate(mdCtx, dataSegment, data.length);
                if (result != 1) {
                    throw new SignatureException("EVP_DigestSignUpdate failed");
                }
            }

            // Get signature length first
            MemorySegment sigLenSegment = confinedArena.allocate(ValueLayout.JAVA_LONG);
            int result = OpenSSLCrypto.EVP_DigestSignFinal(mdCtx, MemorySegment.NULL, sigLenSegment);
            if (result != 1) {
                throw new SignatureException("EVP_DigestSignFinal failed (size query)");
            }

            long sigLen = sigLenSegment.get(ValueLayout.JAVA_LONG, 0);
            MemorySegment sigSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, sigLen);

            // Get actual signature
            result = OpenSSLCrypto.EVP_DigestSignFinal(mdCtx, sigSegment, sigLenSegment);
            if (result != 1) {
                throw new SignatureException("EVP_DigestSignFinal failed");
            }

            sigLen = sigLenSegment.get(ValueLayout.JAVA_LONG, 0);
            byte[] signature = new byte[(int) sigLen];
            sigSegment.asByteBuffer().get(signature);

            return signature;

        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error signing data", e);
        } finally {
            reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (signing || mdCtx == null) {
            throw new SignatureException("Signature not initialized for verification");
        }

        try (Arena confinedArena = Arena.ofConfined()) {
            // Update with buffered data
            byte[] data = dataBuffer.toByteArray();
            if (data.length > 0) {
                MemorySegment dataSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, data.length);
                dataSegment.asByteBuffer().put(data);
                int result = OpenSSLCrypto.EVP_DigestVerifyUpdate(mdCtx, dataSegment, data.length);
                if (result != 1) {
                    throw new SignatureException("EVP_DigestVerifyUpdate failed");
                }
            }

            // Verify signature
            MemorySegment sigSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, sigBytes.length);
            sigSegment.asByteBuffer().put(sigBytes);

            int result = OpenSSLCrypto.EVP_DigestVerifyFinal(mdCtx, sigSegment, sigBytes.length);

            // result == 1 means success, 0 means verification failed, < 0 means error
            return result == 1;

        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error verifying signature", e);
        } finally {
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
        if (mdCtx != null) {
            try {
                OpenSSLCrypto.EVP_MD_CTX_free(mdCtx);
            } catch (Throwable e) {
                // Ignore
            }
            mdCtx = null;
        }
        if (evpPkey != null) {
            try {
                OpenSSLCrypto.EVP_PKEY_free(evpPkey);
            } catch (Throwable e) {
                // Ignore
            }
            evpPkey = null;
        }
        if (arena != null) {
            arena.close();
            arena = null;
        }
        dataBuffer = null;
        pkeyCtxPtr = null;
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
