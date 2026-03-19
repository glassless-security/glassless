package net.glassless.provider.internal.slhdsa;

import static net.glassless.provider.internal.OpenSSLCrypto.loadPrivateKey;
import static net.glassless.provider.internal.OpenSSLCrypto.loadPublicKey;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * SLH-DSA Signature implementation using OpenSSL.
 * Supports all 12 SLH-DSA variants.
 *
 * <p>SLH-DSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class SLHDSASignature extends SignatureSpi {

    protected final String expectedVariant;  // null means accept any SLH-DSA variant
    protected String variant;
    protected byte[] privateKeyEncoded;
    protected byte[] publicKeyEncoded;
    protected final ByteArrayOutputStream dataBuffer;
    protected boolean signing;

    public SLHDSASignature() {
        this(null);
    }

    protected SLHDSASignature(String expectedVariant) {
        this.expectedVariant = expectedVariant;
        this.dataBuffer = new ByteArrayOutputStream();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Private key cannot be null");
        }

        String keyAlgorithm = privateKey.getAlgorithm();
        if (!keyAlgorithm.startsWith("SLH-DSA") && !keyAlgorithm.equals("SLHDSA")) {
            throw new InvalidKeyException("SLH-DSA private key required, got: " + keyAlgorithm);
        }

        if (expectedVariant != null) {
            String normalizedKey = normalizeVariant(keyAlgorithm);
            String normalizedExpected = normalizeVariant(expectedVariant);
            if (!normalizedKey.equals(normalizedExpected)) {
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
        if (!keyAlgorithm.startsWith("SLH-DSA") && !keyAlgorithm.equals("SLHDSA")) {
            throw new InvalidKeyException("SLH-DSA public key required, got: " + keyAlgorithm);
        }

        if (expectedVariant != null) {
            String normalizedKey = normalizeVariant(keyAlgorithm);
            String normalizedExpected = normalizeVariant(expectedVariant);
            if (!normalizedKey.equals(normalizedExpected)) {
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

    private String normalizeVariant(String variant) {
        return variant.toUpperCase().replace("-", "").replace("_", "");
    }

    @Override
    protected void engineUpdate(byte b) {
        dataBuffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
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
           return loadPrivateKey(data, arena, privateKeyEncoded);
        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new SignatureException("SLH-DSA signing failed", e);
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
           return loadPublicKey(sigBytes, data, arena, publicKeyEncoded);
        } catch (SignatureException e) {
            throw e;
        } catch (Throwable e) {
            throw new SignatureException("SLH-DSA verification failed", e);
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
