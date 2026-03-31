package net.glassless.provider.internal.cipher;

public class ARIA_192OfbNoPaddingCipher extends AbstractCipher {
   public ARIA_192OfbNoPaddingCipher() {
      super("aria-192-ofb", CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
