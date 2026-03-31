package net.glassless.provider.internal.cipher;

public class ARIA_256CbcNoPaddingCipher extends AbstractCipher {
   public ARIA_256CbcNoPaddingCipher() {
      super("aria-256-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
