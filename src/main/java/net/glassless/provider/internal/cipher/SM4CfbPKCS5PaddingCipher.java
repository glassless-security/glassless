package net.glassless.provider.internal.cipher;

public class SM4CfbPKCS5PaddingCipher extends AbstractCipher {
   public SM4CfbPKCS5PaddingCipher() {
      super("sm4-cfb", 16, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
