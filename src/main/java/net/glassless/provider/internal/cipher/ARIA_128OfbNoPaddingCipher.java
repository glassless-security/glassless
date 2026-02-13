package net.glassless.provider.internal.cipher;

public class ARIA_128OfbNoPaddingCipher extends AbstractCipher {
   public ARIA_128OfbNoPaddingCipher() {
      super("aria-128-ofb", 16, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
