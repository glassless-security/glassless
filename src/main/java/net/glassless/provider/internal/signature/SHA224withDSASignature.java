package net.glassless.provider.internal.signature;

public class SHA224withDSASignature extends AbstractSignature {
    public SHA224withDSASignature() {
        super("SHA224", KeyType.DSA);
    }
}
