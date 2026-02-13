package net.glassless.provider.internal.signature;

public class SHA1withRSASignature extends AbstractSignature {
    public SHA1withRSASignature() {
        super("SHA1", KeyType.RSA);
    }
}
