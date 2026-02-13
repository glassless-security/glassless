package net.glassless.provider.internal.signature;

public class SHA512withECDSASignature extends AbstractSignature {
    public SHA512withECDSASignature() {
        super("SHA512", KeyType.EC);
    }
}
