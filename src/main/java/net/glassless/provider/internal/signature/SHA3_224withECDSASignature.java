package net.glassless.provider.internal.signature;

public class SHA3_224withECDSASignature extends AbstractSignature {
    public SHA3_224withECDSASignature() {
        super("SHA3-224", KeyType.EC);
    }
}
