package net.glassless.provider.internal.signature;

public class SHA256withRSASignature extends AbstractSignature {
    public SHA256withRSASignature() {
        super("SHA256", KeyType.RSA);
    }
}
