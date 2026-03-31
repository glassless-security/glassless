package net.glassless.provider.internal.cipher;

public class AES_256EcbPKCS5PaddingCipher extends AbstractCipher {
   public AES_256EcbPKCS5PaddingCipher() {
      super("aes-256-ecb", CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
