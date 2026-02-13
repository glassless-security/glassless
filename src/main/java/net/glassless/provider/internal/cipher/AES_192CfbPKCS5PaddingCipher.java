package net.glassless.provider.internal.cipher;

public class AES_192CfbPKCS5PaddingCipher extends AbstractCipher {
   public AES_192CfbPKCS5PaddingCipher() {
      super("aes-192-cfb", 24, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
