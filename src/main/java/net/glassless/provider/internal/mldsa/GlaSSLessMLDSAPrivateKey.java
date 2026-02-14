package net.glassless.provider.internal.mldsa;

import java.security.PrivateKey;
import java.util.Arrays;

import javax.security.auth.Destroyable;

/**
 * ML-DSA private key implementation with Destroyable support.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 variants.
 */
public class GlaSSLessMLDSAPrivateKey implements PrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private byte[] encoded;
    private boolean destroyed = false;

    public GlaSSLessMLDSAPrivateKey(String algorithm, byte[] encoded) {
        this.algorithm = algorithm;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (destroyed) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return encoded.clone();
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(encoded, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof GlaSSLessMLDSAPrivateKey other)) return false;
        if (destroyed || other.destroyed) return false;
        return algorithm.equals(other.algorithm) && Arrays.equals(encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return destroyed ? 0 : Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlaSSLessMLDSAPrivateKey [algorithm=" + algorithm + ", destroyed=" + destroyed + "]";
    }
}
