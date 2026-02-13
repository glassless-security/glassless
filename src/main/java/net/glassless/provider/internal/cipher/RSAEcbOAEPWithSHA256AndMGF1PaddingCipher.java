package net.glassless.provider.internal.cipher;

public class RSAEcbOAEPWithSHA256AndMGF1PaddingCipher extends AbstractRSACipher {
    public RSAEcbOAEPWithSHA256AndMGF1PaddingCipher() {
        super(RSAPadding.OAEPPADDING, "SHA256");
    }
}
