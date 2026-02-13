package net.glassless.provider.internal.cipher;

public class ARIA_192CbcNoPaddingCipher extends AbstractCipher {
   public ARIA_192CbcNoPaddingCipher() {
      super("aria-192-cbc", 24, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
