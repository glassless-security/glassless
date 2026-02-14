package net.glassless.provider.internal.mldsa;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * ML-DSA Signature implementation using OpenSSL.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.
 *
 * <p>ML-DSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class MLDSASignature extends SignatureSpi {

    protected final String expectedVariant;  // null means accept any ML-DSA variant
    protected String variant;
    protected byte[] privateKeyEncoded;
    protected byte[] publicKeyEncoded;
    protected ByteArrayOutputStream dataBuffer;
    protected boolean signing;

    public MLDSASignature() {
        this(null);
    }

    protected MLDSASignature(String expectedVariant) {
        this.expectedVariant = expectedVariant;
        this.dataBuffer = new ByteArrayOutputStream();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Private key cannot be null");
        }

        String keyAlgorithm = privateKey.getAlgorithm();
        if (!keyAlgorithm.startsWith("ML-DSA") && !keyAlgorithm.equals("MLDSA")) {
            throw new InvalidKeyException("ML-DSA private key required, got: " + keyAlgorithm);
        }

        if (expectedVariant != null) {
            String normalizedKey = keyAlgorithm.replace("-", "").replace("_", "").toUpperCase();
            String normalizedExpected = expectedVariant.replace("-", "").replace("_", "").toUpperCase();
            if (!normalizedKey.contains(normalizedExpected.replace("MLDSA", ""))) {
                throw new InvalidKeyException("Key variant " + keyAlgorithm +
                    " does not match expected variant " + expectedVariant);
            }
        }

        this.variant = keyAlgorithm;
        this.privateKeyEncoded = privateKey.getEncoded();
        if (this.privateKeyEncoded == null) {
            throw new InvalidKeyException("Private key encoding is null");
        }

        this.publicKeyEncoded = null;
        this.dataBuffer.reset();
        this.signing = true;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("Public key cannot be null");
        }

        String keyAlgorithm = publicKey.getAlgorithm();
        if (!keyAlgorithm.startsWith("ML-DSA") && !keyAlgorithm.equals("MLDSA")) {
            throw new InvalidKeyException("ML-DSA public key required, got: " + keyAlgorithm);
        }

        if (expectedVariant != null) {
            String normalizedKey = keyAlgorithm.replace("-", "").replace("_", "").toUpperCase();
            String normalizedExpected = expectedVariant.replace("-", "").replace("_", "").toUpperCase();
            if (!normalizedKey.contains(normalizedExpected.replace("MLDSA", ""))) {
                throw new InvalidKeyException("Key variant " + keyAlgorithm +
                    " does not match expected variant " + expectedVariant);
            }
        }

        this.variant = keyAlgorithm;
        this.publicKeyEncoded = publicKey.getEncoded();
        if (this.publicKeyEncoded == null) {
            throw new InvalidKeyException("Public key encoding is null");
        }

        this.privateKeyEncoded = null;
        this.dataBuffer.reset();
        this.signing = false;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        dataBuffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        dataBuffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!signing) {
            throw new SignatureException("Not initialized for signing");
        }

        byte[] data = dataBuffer.toByteArray();
        dataBuffer.reset();

        try (Arena arena = Arena.ofConfined()) {
            // Load the private key
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded, arena);
            if (pkey == null || pkey.address() == 0) {
                throw new SignatureException("Failed to load private key");
            }

            try {
                // Create message digest context for signing
                MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
                if (mdCtx == null || mdCtx.address() == 0) {
                    throw new SignatureException("Failed to create EVP_MD_CTX");
                }

                try {
                    // Initialize signing - ML-DSA uses NULL for digest (built into algorithm)
                    int result = OpenSSLCrypto.EVP_DigestSignInit(mdCtx, MemorySegment.NULL,
                        MemorySegment.NULL, MemorySegment.NULL, pkey);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestSignInit failed");
                    }

                    // Get required signature length
                    MemorySegment sigLenPtr = arena.allocate(ValueLayout.JAVA_LONG);

                    // Prepare data segment
                    MemorySegment dataSegment;
                    if (data.length > 0) {
                        dataSegment = arena.allocate(ValueLayout.JAVA_BYTE, data.length);
                        dataSegment.asByteBuffer().put(data);
                    } else {
                        dataSegment = MemorySegment.NULL;
                    }

                    // Get required signature length
                    result = OpenSSLCrypto.EVP_DigestSign(mdCtx, MemorySegment.NULL, sigLenPtr,
                        dataSegment, data.length);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestSign (get length) failed");
                    }

                    long sigLen = sigLenPtr.get(ValueLayout.JAVA_LONG, 0);
                    MemorySegment sigBuffer = arena.allocate(ValueLayout.JAVA_BYTE, sigLen);

                    // Perform the actual signing
                    result = OpenSSLCrypto.EVP_DigestSign(mdCtx, sigBuffer, sigLenPtr,
                        dataSegment, data.length);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestSign failed");
                    }

                    // Get actual signature length and extract
                    long actualLen = sigLenPtr.get(ValueLayout.JAVA_LONG, 0);
                    byte[] signature = new byte[(int) actualLen];
                    sigBuffer.asByteBuffer().get(signature);

                    return signature;
                } finally {
                    OpenSSLCrypto.EVP_MD_CTX_free(mdCtx);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new SignatureException("ML-DSA signing failed", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (signing) {
            throw new SignatureException("Not initialized for verification");
        }

        byte[] data = dataBuffer.toByteArray();
        dataBuffer.reset();

        try (Arena arena = Arena.ofConfined()) {
            // Load the public key
            MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
            if (pkey == null || pkey.address() == 0) {
                throw new SignatureException("Failed to load public key");
            }

            try {
                // Create message digest context for verification
                MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
                if (mdCtx == null || mdCtx.address() == 0) {
                    throw new SignatureException("Failed to create EVP_MD_CTX");
                }

                try {
                    // Initialize verification - ML-DSA uses NULL for digest
                    int result = OpenSSLCrypto.EVP_DigestVerifyInit(mdCtx, MemorySegment.NULL,
                        MemorySegment.NULL, MemorySegment.NULL, pkey);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestVerifyInit failed");
                    }

                    // Prepare signature segment
                    MemorySegment sigSegment = arena.allocate(ValueLayout.JAVA_BYTE, sigBytes.length);
                    sigSegment.asByteBuffer().put(sigBytes);

                    // Prepare data segment
                    MemorySegment dataSegment;
                    if (data.length > 0) {
                        dataSegment = arena.allocate(ValueLayout.JAVA_BYTE, data.length);
                        dataSegment.asByteBuffer().put(data);
                    } else {
                        dataSegment = MemorySegment.NULL;
                    }

                    // Single-shot verification
                    result = OpenSSLCrypto.EVP_DigestVerify(mdCtx, sigSegment, sigBytes.length,
                        dataSegment, data.length);

                    return result == 1;
                } finally {
                    OpenSSLCrypto.EVP_MD_CTX_free(mdCtx);
                }
            } finally {
                OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new SignatureException("ML-DSA verification failed", e);
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("No parameters supported");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("No parameters supported");
    }
}
