package net.glassless.provider.internal.cipher;

public class AES_128EcbPKCS5PaddingCipher extends AbstractCipher {
   public AES_128EcbPKCS5PaddingCipher() {
      super("aes-128-ecb", 16, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
