package net.glassless.provider.internal.signature;

public class SHA3_512withECDSASignature extends AbstractSignature {
    public SHA3_512withECDSASignature() {
        super("SHA3-512", KeyType.EC);
    }
}
