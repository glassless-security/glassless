package net.glassless.provider.internal.signature;

public class SHA512_224withRSASignature extends AbstractSignature {
    public SHA512_224withRSASignature() {
        super("SHA512-224", KeyType.RSA);
    }
}
