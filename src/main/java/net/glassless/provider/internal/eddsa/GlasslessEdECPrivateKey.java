package net.glassless.provider.internal.eddsa;

import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;

/**
 * EdDSA private key implementation for Ed25519 and Ed448.
 */
public class GlasslessEdECPrivateKey implements EdECPrivateKey {

    private static final long serialVersionUID = 1L;

    private final NamedParameterSpec params;
    private final byte[] keyBytes;
    private final byte[] encoded;

    public GlasslessEdECPrivateKey(NamedParameterSpec params, byte[] keyBytes, byte[] encoded) {
        this.params = params;
        this.keyBytes = keyBytes.clone();
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
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
    public NamedParameterSpec getParams() {
        return params;
    }

    @Override
    public Optional<byte[]> getBytes() {
        return Optional.of(keyBytes.clone());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof EdECPrivateKey other)) return false;
        if (!params.getName().equals(other.getParams().getName())) return false;
        Optional<byte[]> otherBytes = other.getBytes();
        if (otherBytes.isEmpty()) return false;
        return Arrays.equals(keyBytes, otherBytes.get());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "GlasslessEdECPrivateKey [algorithm=" + params.getName() + "]";
    }

    /**
     * Clears the private key material from memory.
     */
    public void destroy() {
        Arrays.fill(keyBytes, (byte) 0);
        Arrays.fill(encoded, (byte) 0);
    }
}
