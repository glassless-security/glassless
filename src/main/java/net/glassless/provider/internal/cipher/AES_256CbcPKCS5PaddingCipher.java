package net.glassless.provider.internal.cipher;

public class AES_256CbcPKCS5PaddingCipher extends AbstractCipher {
   public AES_256CbcPKCS5PaddingCipher() {
      super("aes-256-cbc", 32, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
