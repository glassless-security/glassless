package net.glassless.provider.internal.xdh;

import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;

/**
 * XDH private key implementation for X25519 and X448.
 */
public class GlaSSLessXECPrivateKey implements XECPrivateKey {

    private static final long serialVersionUID = 1L;

    private final NamedParameterSpec params;
    private final byte[] scalar;
    private final byte[] encoded;

    public GlaSSLessXECPrivateKey(NamedParameterSpec params, byte[] scalar, byte[] encoded) {
        this.params = params;
        this.scalar = scalar.clone();
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
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
    public Optional<byte[]> getScalar() {
        return Optional.of(scalar.clone());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof XECPrivateKey other)) return false;
        if (!params.getName().equals(((NamedParameterSpec) other.getParams()).getName())) return false;
        Optional<byte[]> otherScalar = other.getScalar();
        if (otherScalar.isEmpty()) return false;
        return Arrays.equals(scalar, otherScalar.get());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlaSSLessXECPrivateKey [algorithm=" + params.getName() + "]";
    }

    /**
     * Clears the private key material from memory.
     */
    public void destroy() {
        Arrays.fill(scalar, (byte) 0);
        Arrays.fill(encoded, (byte) 0);
    }
}
