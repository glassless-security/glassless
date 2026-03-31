package net.glassless.provider.internal.cipher;

public class ARIA_128OfbNoPaddingCipher extends AbstractCipher {
   public ARIA_128OfbNoPaddingCipher() {
      super("aria-128-ofb", CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
