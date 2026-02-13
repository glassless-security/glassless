package net.glassless.provider.internal.cipher;

public class ARIA_256OfbNoPaddingCipher extends AbstractCipher {
   public ARIA_256OfbNoPaddingCipher() {
      super("aria-256-ofb", 32, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
