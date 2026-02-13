package net.glassless.provider.internal.cipher;

public class AES_128CbcPKCS5PaddingCipher extends AbstractCipher {
   public AES_128CbcPKCS5PaddingCipher() {
      super("aes-128-cbc", 16, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
