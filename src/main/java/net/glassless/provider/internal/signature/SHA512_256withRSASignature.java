package net.glassless.provider.internal.signature;

public class SHA512_256withRSASignature extends AbstractSignature {
    public SHA512_256withRSASignature() {
        super("SHA512-256", KeyType.RSA);
    }
}
