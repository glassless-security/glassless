package net.glassless.provider.internal.signature;

public class SHA224withECDSASignature extends AbstractSignature {
    public SHA224withECDSASignature() {
        super("SHA224", KeyType.EC);
    }
}
