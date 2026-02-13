package net.glassless.provider.internal.cipher;

public class RSAEcbOAEPWithSHA1AndMGF1PaddingCipher extends AbstractRSACipher {
    public RSAEcbOAEPWithSHA1AndMGF1PaddingCipher() {
        super(RSAPadding.OAEPPADDING, "SHA1");
    }
}
