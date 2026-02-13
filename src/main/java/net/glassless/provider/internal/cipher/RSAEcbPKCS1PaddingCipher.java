package net.glassless.provider.internal.cipher;

public class RSAEcbPKCS1PaddingCipher extends AbstractRSACipher {
    public RSAEcbPKCS1PaddingCipher() {
        super(RSAPadding.PKCS1PADDING, null);
    }
}
