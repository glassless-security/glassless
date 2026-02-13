package net.glassless.provider.internal.cipher;

public class ARIA_192OfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_192OfbPKCS5PaddingCipher() {
      super("aria-192-ofb", 24, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
