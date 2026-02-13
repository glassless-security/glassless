package net.glassless.provider.internal.cipher;

public class SM4EcbPKCS5PaddingCipher extends AbstractCipher {
   public SM4EcbPKCS5PaddingCipher() {
      super("sm4-ecb", 16, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
