package net.glassless.provider.internal.signature;

public class SHA384withDSASignature extends AbstractSignature {
    public SHA384withDSASignature() {
        super("SHA384", KeyType.DSA);
    }
}
