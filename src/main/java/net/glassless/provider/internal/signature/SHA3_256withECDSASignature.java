package net.glassless.provider.internal.signature;

public class SHA3_256withECDSASignature extends AbstractSignature {
    public SHA3_256withECDSASignature() {
        super("SHA3-256", KeyType.EC);
    }
}
