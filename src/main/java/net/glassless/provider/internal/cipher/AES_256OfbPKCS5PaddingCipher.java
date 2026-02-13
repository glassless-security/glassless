package net.glassless.provider.internal.cipher;

public class AES_256OfbPKCS5PaddingCipher extends AbstractCipher {
   public AES_256OfbPKCS5PaddingCipher() {
      super("aes-256-ofb", 32, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
