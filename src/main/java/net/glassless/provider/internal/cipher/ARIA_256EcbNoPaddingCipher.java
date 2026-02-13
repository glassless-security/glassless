package net.glassless.provider.internal.cipher;

public class ARIA_256EcbNoPaddingCipher extends AbstractCipher {
   public ARIA_256EcbNoPaddingCipher() {
      super("aria-256-ecb", 32, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
