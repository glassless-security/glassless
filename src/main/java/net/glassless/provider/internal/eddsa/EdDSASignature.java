package net.glassless.provider.internal.eddsa;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
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
 * <p>
 * EdDSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class EdDSASignature extends SignatureSpi {

    private final String expectedCurve;  // null means accept any EdDSA curve
    private NamedParameterSpec params;
    private byte[] privateKeyEncoded;
    private byte[] publicKeyEncoded;
    private final ByteArrayOutputStream dataBuffer;
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
           return OpenSSLCrypto.loadPrivateKey(data, arena, privateKeyEncoded);
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
           return OpenSSLCrypto.loadPublicKey(sigBytes, data, arena, publicKeyEncoded);
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
