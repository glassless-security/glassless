package net.glassless.provider.internal.cipher;

public class ARIA_128CtrNoPaddingCipher extends AbstractCipher {
   public ARIA_128CtrNoPaddingCipher() {
      super("aria-128-ctr", CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
