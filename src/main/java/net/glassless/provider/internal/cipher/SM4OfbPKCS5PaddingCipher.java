package net.glassless.provider.internal.cipher;

public class SM4OfbPKCS5PaddingCipher extends AbstractCipher {
   public SM4OfbPKCS5PaddingCipher() {
      super("sm4-ofb", CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
