package net.glassless.provider.internal.cipher;

public class AES_192EcbPKCS5PaddingCipher extends AbstractCipher {
   public AES_192EcbPKCS5PaddingCipher() {
      super("aes-192-ecb", 24, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
