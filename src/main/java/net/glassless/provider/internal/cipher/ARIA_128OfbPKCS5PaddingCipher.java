package net.glassless.provider.internal.cipher;

public class ARIA_128OfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128OfbPKCS5PaddingCipher() {
      super("aria-128-ofb", CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
