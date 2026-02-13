package net.glassless.provider.internal.signature;

public class SHA256withDSASignature extends AbstractSignature {
    public SHA256withDSASignature() {
        super("SHA256", KeyType.DSA);
    }
}
