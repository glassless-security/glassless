package net.glassless.provider.internal.cipher;

public class ARIA_256CbcNoPaddingCipher extends AbstractCipher {
   public ARIA_256CbcNoPaddingCipher() {
      super("aria-256-cbc", 32, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
