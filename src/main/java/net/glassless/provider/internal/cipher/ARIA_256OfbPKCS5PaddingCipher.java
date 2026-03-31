package net.glassless.provider.internal.cipher;

public class ARIA_256OfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_256OfbPKCS5PaddingCipher() {
      super("aria-256-ofb", CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
