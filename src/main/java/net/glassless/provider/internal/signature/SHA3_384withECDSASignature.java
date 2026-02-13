package net.glassless.provider.internal.signature;

public class SHA3_384withECDSASignature extends AbstractSignature {
    public SHA3_384withECDSASignature() {
        super("SHA3-384", KeyType.EC);
    }
}
