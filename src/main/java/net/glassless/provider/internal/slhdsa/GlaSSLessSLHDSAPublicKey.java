package net.glassless.provider.internal.slhdsa;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * SLH-DSA public key implementation.
 * Supports all 12 SLH-DSA variants (SHA2/SHAKE x 128/192/256 x s/f).
 */
public class GlaSSLessSLHDSAPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final byte[] encoded;

    public GlaSSLessSLHDSAPublicKey(String algorithm, byte[] encoded) {
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
        if (!(obj instanceof GlaSSLessSLHDSAPublicKey other)) return false;
        return algorithm.equals(other.algorithm) && Arrays.equals(encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlaSSLessSLHDSAPublicKey [algorithm=" + algorithm + "]";
    }
}
