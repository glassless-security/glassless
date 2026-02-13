package net.glassless.provider.internal.cipher;

public class AES_128CfbPKCS5PaddingCipher extends AbstractCipher {
   public AES_128CfbPKCS5PaddingCipher() {
      super("aes-128-cfb", 16, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
