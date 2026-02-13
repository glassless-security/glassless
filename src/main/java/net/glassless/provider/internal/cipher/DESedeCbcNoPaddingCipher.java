package net.glassless.provider.internal.cipher;

public class DESedeCbcNoPaddingCipher extends AbstractCipher {
    public DESedeCbcNoPaddingCipher() {
        super("des-ede3-cbc", 24, CipherMode.CBC, CipherPadding.NOPADDING);
    }
}
