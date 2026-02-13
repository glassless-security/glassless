package net.glassless.provider.internal.cipher;

public class AES_256CfbPKCS5PaddingCipher extends AbstractCipher {
   public AES_256CfbPKCS5PaddingCipher() {
      super("aes-256-cfb", 32, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
