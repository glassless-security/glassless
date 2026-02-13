package net.glassless.provider.internal.cipher;

public class ARIA_192EcbNoPaddingCipher extends AbstractCipher {
   public ARIA_192EcbNoPaddingCipher() {
      super("aria-192-ecb", 24, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
