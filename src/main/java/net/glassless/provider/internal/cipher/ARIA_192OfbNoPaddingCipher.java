package net.glassless.provider.internal.cipher;

public class ARIA_192OfbNoPaddingCipher extends AbstractCipher {
   public ARIA_192OfbNoPaddingCipher() {
      super("aria-192-ofb", 24, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
