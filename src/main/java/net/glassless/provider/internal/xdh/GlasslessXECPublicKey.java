package net.glassless.provider.internal.xdh;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * XDH public key implementation for X25519 and X448.
 */
public class GlasslessXECPublicKey implements XECPublicKey {

    private static final long serialVersionUID = 1L;

    private final NamedParameterSpec params;
    private final BigInteger u;
    private final byte[] encoded;

    public GlasslessXECPublicKey(NamedParameterSpec params, BigInteger u, byte[] encoded) {
        this.params = params;
        this.u = u;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
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
    public AlgorithmParameterSpec getParams() {
        return params;
    }

    @Override
    public BigInteger getU() {
        return u;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof XECPublicKey other)) return false;
        return u.equals(other.getU()) &&
               params.getName().equals(((NamedParameterSpec) other.getParams()).getName());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlasslessXECPublicKey [algorithm=" + params.getName() + "]";
    }
}
