package net.glassless.provider.internal.signature;

public class SHA224withRSASignature extends AbstractSignature {
    public SHA224withRSASignature() {
        super("SHA224", KeyType.RSA);
    }
}
