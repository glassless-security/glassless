package net.glassless.provider.internal.eddsa;

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
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.NamedParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * EdDSA Signature implementation using OpenSSL.
 * Supports Ed25519 and Ed448.
 *
 * EdDSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class EdDSASignature extends SignatureSpi {

    private final String expectedCurve;  // null means accept any EdDSA curve
    private NamedParameterSpec params;
    private byte[] privateKeyEncoded;
    private byte[] publicKeyEncoded;
    private ByteArrayOutputStream dataBuffer;
    private boolean signing;

    public EdDSASignature() {
        this(null);
    }

    protected EdDSASignature(String expectedCurve) {
        this.expectedCurve = expectedCurve;
        this.dataBuffer = new ByteArrayOutputStream();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof EdECPrivateKey edKey)) {
            throw new InvalidKeyException("EdECPrivateKey required, got: " +
                (privateKey == null ? "null" : privateKey.getClass().getName()));
        }

        this.params = edKey.getParams();
        validateCurve(params.getName());

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
        if (!(publicKey instanceof EdECPublicKey edKey)) {
            throw new InvalidKeyException("EdECPublicKey required, got: " +
                (publicKey == null ? "null" : publicKey.getClass().getName()));
        }

        this.params = edKey.getParams();
        validateCurve(params.getName());

        this.publicKeyEncoded = publicKey.getEncoded();
        if (this.publicKeyEncoded == null) {
            throw new InvalidKeyException("Public key encoding is null");
        }

        this.privateKeyEncoded = null;
        this.dataBuffer.reset();
        this.signing = false;
    }

    private void validateCurve(String curveName) throws InvalidKeyException {
        if (expectedCurve != null && !expectedCurve.equalsIgnoreCase(curveName)) {
            throw new InvalidKeyException("Key curve " + curveName +
                " does not match expected curve " + expectedCurve);
        }
        if (!curveName.equalsIgnoreCase("Ed25519") && !curveName.equalsIgnoreCase("Ed448")) {
            throw new InvalidKeyException("Unsupported EdDSA curve: " + curveName);
        }
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
            if (pkey.equals(MemorySegment.NULL)) {
                throw new SignatureException("Failed to load private key");
            }

            try {
                // Create message digest context for signing
                MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
                if (mdCtx.equals(MemorySegment.NULL)) {
                    throw new SignatureException("Failed to create EVP_MD_CTX");
                }

                try {
                    // Initialize signing - EdDSA uses NULL for digest (it's built into the algorithm)
                    int result = OpenSSLCrypto.EVP_DigestSignInit(mdCtx, MemorySegment.NULL,
                        MemorySegment.NULL, MemorySegment.NULL, pkey);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestSignInit failed");
                    }

                    // For EdDSA, use single-shot EVP_DigestSign
                    // First, get the signature length by calling with NULL output
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
            throw new SignatureException("EdDSA signing failed", e);
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
            if (pkey.equals(MemorySegment.NULL)) {
                throw new SignatureException("Failed to load public key");
            }

            try {
                // Create message digest context for verification
                MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
                if (mdCtx.equals(MemorySegment.NULL)) {
                    throw new SignatureException("Failed to create EVP_MD_CTX");
                }

                try {
                    // Initialize verification - EdDSA uses NULL for digest
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
            throw new SignatureException("EdDSA verification failed", e);
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
