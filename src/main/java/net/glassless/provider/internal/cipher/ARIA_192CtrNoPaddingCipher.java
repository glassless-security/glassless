package net.glassless.provider.internal.cipher;

public class ARIA_192CtrNoPaddingCipher extends AbstractCipher {
   public ARIA_192CtrNoPaddingCipher() {
      super("aria-192-ctr", 24, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
