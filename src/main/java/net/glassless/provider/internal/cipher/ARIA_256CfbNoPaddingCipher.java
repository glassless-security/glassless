package net.glassless.provider.internal.cipher;

public class ARIA_256CfbNoPaddingCipher extends AbstractCipher {
   public ARIA_256CfbNoPaddingCipher() {
      super("aria-256-cfb", CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
