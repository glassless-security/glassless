package net.glassless.provider.internal.cipher;

public class DESedeEcbPKCS5PaddingCipher extends AbstractCipher {
    public DESedeEcbPKCS5PaddingCipher() {
        super("des-ede3-ecb", 24, CipherMode.ECB, CipherPadding.PKCS5PADDING);
    }
}
