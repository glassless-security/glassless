package net.glassless.provider.internal.signature;

public class SHA384withRSASignature extends AbstractSignature {
    public SHA384withRSASignature() {
        super("SHA384", KeyType.RSA);
    }
}
