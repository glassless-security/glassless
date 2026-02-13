package net.glassless.provider.internal.cipher;

public class ARIA_128EcbNoPaddingCipher extends AbstractCipher {
   public ARIA_128EcbNoPaddingCipher() {
      super("aria-128-ecb", 16, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
