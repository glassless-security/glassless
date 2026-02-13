package net.glassless.provider.internal.cipher;

public class ARIA_256CtrNoPaddingCipher extends AbstractCipher {
   public ARIA_256CtrNoPaddingCipher() {
      super("aria-256-ctr", 32, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
