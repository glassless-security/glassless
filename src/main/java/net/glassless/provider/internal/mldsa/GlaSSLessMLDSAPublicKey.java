package net.glassless.provider.internal.mldsa;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * ML-DSA public key implementation.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 variants.
 */
public class GlaSSLessMLDSAPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final byte[] encoded;

    public GlaSSLessMLDSAPublicKey(String algorithm, byte[] encoded) {
        this.algorithm = algorithm;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof GlaSSLessMLDSAPublicKey other)) return false;
        return algorithm.equals(other.algorithm) && Arrays.equals(encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlaSSLessMLDSAPublicKey [algorithm=" + algorithm + "]";
    }
}
