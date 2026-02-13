package net.glassless.provider.internal.signature;

public class SHA512withDSASignature extends AbstractSignature {
    public SHA512withDSASignature() {
        super("SHA512", KeyType.DSA);
    }
}
