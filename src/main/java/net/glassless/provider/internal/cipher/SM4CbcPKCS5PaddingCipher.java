package net.glassless.provider.internal.cipher;

public class SM4CbcPKCS5PaddingCipher extends AbstractCipher {
   public SM4CbcPKCS5PaddingCipher() {
      super("sm4-cbc", 16, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
