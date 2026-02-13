package net.glassless.provider.internal.cipher;

public class ARIA_128OfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128OfbPKCS5PaddingCipher() {
      super("aria-128-ofb", 16, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
