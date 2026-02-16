package net.glassless.provider.internal.eddsa;

import java.io.ByteArrayOutputStream;
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

        try {
            // Load the private key
            int pkey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded);
            if (pkey == 0) {
                throw new SignatureException("Failed to load private key");
            }

            try {
                // Create message digest context for signing
                int mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
                if (mdCtx == 0) {
                    throw new SignatureException("Failed to create EVP_MD_CTX");
                }

                try {
                    // Initialize signing - EdDSA uses NULL for digest (it's built into the algorithm)
                    int result = OpenSSLCrypto.EVP_DigestSignInit(mdCtx, 0,
                        0, 0, pkey);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestSignInit failed");
                    }

                    // For EdDSA, use single-shot EVP_DigestSign
                    // First, get the signature length by calling with NULL output
                    int sigLenPtr = OpenSSLCrypto.malloc(4);
                    try {
                        OpenSSLCrypto.memory().writeI32(sigLenPtr, 0);

                        // Prepare data
                        int dataPtr;
                        if (data.length > 0) {
                            dataPtr = OpenSSLCrypto.malloc(data.length);
                            OpenSSLCrypto.memory().write(dataPtr, data);
                        } else {
                            dataPtr = 0;
                        }

                        try {
                            // Get required signature length
                            result = OpenSSLCrypto.EVP_DigestSign(mdCtx, 0, sigLenPtr,
                                dataPtr, data.length);
                            if (result != 1) {
                                throw new SignatureException("EVP_DigestSign (get length) failed");
                            }

                            int sigLen = OpenSSLCrypto.memory().readInt(sigLenPtr);
                            int sigBuffer = OpenSSLCrypto.malloc(sigLen);
                            try {
                                // Perform the actual signing
                                result = OpenSSLCrypto.EVP_DigestSign(mdCtx, sigBuffer, sigLenPtr,
                                    dataPtr, data.length);
                                if (result != 1) {
                                    throw new SignatureException("EVP_DigestSign failed");
                                }

                                // Get actual signature length and extract
                                int actualLen = OpenSSLCrypto.memory().readInt(sigLenPtr);
                                byte[] signature = OpenSSLCrypto.memory().readBytes(sigBuffer, actualLen);

                                return signature;
                            } finally {
                                OpenSSLCrypto.free(sigBuffer);
                            }
                        } finally {
                            if (dataPtr != 0) {
                                OpenSSLCrypto.free(dataPtr);
                            }
                        }
                    } finally {
                        OpenSSLCrypto.free(sigLenPtr);
                    }
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

        try {
            // Load the public key
            int pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded);
            if (pkey == 0) {
                throw new SignatureException("Failed to load public key");
            }

            try {
                // Create message digest context for verification
                int mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
                if (mdCtx == 0) {
                    throw new SignatureException("Failed to create EVP_MD_CTX");
                }

                try {
                    // Initialize verification - EdDSA uses NULL for digest
                    int result = OpenSSLCrypto.EVP_DigestVerifyInit(mdCtx, 0,
                        0, 0, pkey);
                    if (result != 1) {
                        throw new SignatureException("EVP_DigestVerifyInit failed");
                    }

                    // Prepare signature
                    int sigPtr = OpenSSLCrypto.malloc(sigBytes.length);
                    try {
                        OpenSSLCrypto.memory().write(sigPtr, sigBytes);

                        // Prepare data
                        int dataPtr;
                        if (data.length > 0) {
                            dataPtr = OpenSSLCrypto.malloc(data.length);
                            OpenSSLCrypto.memory().write(dataPtr, data);
                        } else {
                            dataPtr = 0;
                        }

                        try {
                            // Single-shot verification
                            result = OpenSSLCrypto.EVP_DigestVerify(mdCtx, sigPtr, sigBytes.length,
                                dataPtr, data.length);

                            return result == 1;
                        } finally {
                            if (dataPtr != 0) {
                                OpenSSLCrypto.free(dataPtr);
                            }
                        }
                    } finally {
                        OpenSSLCrypto.free(sigPtr);
                    }
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
