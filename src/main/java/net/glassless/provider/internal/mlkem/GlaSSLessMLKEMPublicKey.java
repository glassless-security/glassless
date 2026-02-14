package net.glassless.provider.internal.mlkem;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * ML-KEM public key implementation.
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 variants.
 */
public class GlaSSLessMLKEMPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final byte[] encoded;

    public GlaSSLessMLKEMPublicKey(String algorithm, byte[] encoded) {
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
        if (!(obj instanceof GlaSSLessMLKEMPublicKey other)) return false;
        return algorithm.equals(other.algorithm) && Arrays.equals(encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlaSSLessMLKEMPublicKey [algorithm=" + algorithm + "]";
    }
}
