package net.glassless.provider.internal.cipher;

public class ARIA_192CfbNoPaddingCipher extends AbstractCipher {
   public ARIA_192CfbNoPaddingCipher() {
      super("aria-192-cfb", 24, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
