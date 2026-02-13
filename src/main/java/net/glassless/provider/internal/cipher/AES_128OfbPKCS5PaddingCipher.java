package net.glassless.provider.internal.cipher;

public class AES_128OfbPKCS5PaddingCipher extends AbstractCipher {
   public AES_128OfbPKCS5PaddingCipher() {
      super("aes-128-ofb", 16, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
