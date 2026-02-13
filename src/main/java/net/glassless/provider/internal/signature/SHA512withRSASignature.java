package net.glassless.provider.internal.signature;

public class SHA512withRSASignature extends AbstractSignature {
    public SHA512withRSASignature() {
        super("SHA512", KeyType.RSA);
    }
}
