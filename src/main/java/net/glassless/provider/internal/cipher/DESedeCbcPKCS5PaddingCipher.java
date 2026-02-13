package net.glassless.provider.internal.cipher;

public class DESedeCbcPKCS5PaddingCipher extends AbstractCipher {
    public DESedeCbcPKCS5PaddingCipher() {
        super("des-ede3-cbc", 24, CipherMode.CBC, CipherPadding.PKCS5PADDING);
    }
}
