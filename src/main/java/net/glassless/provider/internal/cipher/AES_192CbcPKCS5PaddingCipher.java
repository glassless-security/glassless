package net.glassless.provider.internal.cipher;

public class AES_192CbcPKCS5PaddingCipher extends AbstractCipher {
   public AES_192CbcPKCS5PaddingCipher() {
      super("aes-192-cbc", 24, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
