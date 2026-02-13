package net.glassless.provider.internal.eddsa;

import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * EdDSA public key implementation for Ed25519 and Ed448.
 */
public class GlasslessEdECPublicKey implements EdECPublicKey {

    private static final long serialVersionUID = 1L;

    private final NamedParameterSpec params;
    private final EdECPoint point;
    private final byte[] encoded;

    public GlasslessEdECPublicKey(NamedParameterSpec params, EdECPoint point, byte[] encoded) {
        this.params = params;
        this.point = point;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
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
    public NamedParameterSpec getParams() {
        return params;
    }

    @Override
    public EdECPoint getPoint() {
        return point;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof EdECPublicKey other)) return false;
        return params.getName().equals(other.getParams().getName()) &&
               point.equals(other.getPoint());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlasslessEdECPublicKey [algorithm=" + params.getName() + "]";
    }
}
