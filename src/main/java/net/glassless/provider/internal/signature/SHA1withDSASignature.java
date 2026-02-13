package net.glassless.provider.internal.signature;

public class SHA1withDSASignature extends AbstractSignature {
    public SHA1withDSASignature() {
        super("SHA1", KeyType.DSA);
    }
}
