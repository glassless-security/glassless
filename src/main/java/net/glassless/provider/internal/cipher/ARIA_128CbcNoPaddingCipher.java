package net.glassless.provider.internal.cipher;

public class ARIA_128CbcNoPaddingCipher extends AbstractCipher {
   public ARIA_128CbcNoPaddingCipher() {
      super("aria-128-cbc", 16, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
