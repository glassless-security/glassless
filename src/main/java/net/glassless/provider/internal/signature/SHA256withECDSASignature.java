package net.glassless.provider.internal.signature;

public class SHA256withECDSASignature extends AbstractSignature {
    public SHA256withECDSASignature() {
        super("SHA256", KeyType.EC);
    }
}
