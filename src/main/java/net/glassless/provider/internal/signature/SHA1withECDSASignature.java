package net.glassless.provider.internal.signature;

public class SHA1withECDSASignature extends AbstractSignature {
    public SHA1withECDSASignature() {
        super("SHA1", KeyType.EC);
    }
}
