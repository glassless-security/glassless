package net.glassless.provider.internal.cipher;

public class AES_192OfbPKCS5PaddingCipher extends AbstractCipher {
   public AES_192OfbPKCS5PaddingCipher() {
      super("aes-192-ofb", 24, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
