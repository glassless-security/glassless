package net.glassless.provider.internal.signature;

public class SHA384withECDSASignature extends AbstractSignature {
    public SHA384withECDSASignature() {
        super("SHA384", KeyType.EC);
    }
}
