package net.glassless.provider.internal.cipher;

public class RSAEcbNoPaddingCipher extends AbstractRSACipher {
    public RSAEcbNoPaddingCipher() {
        super(RSAPadding.NOPADDING, null);
    }
}
