package net.glassless.provider.internal.cipher;

public class ARIA_128CfbNoPaddingCipher extends AbstractCipher {
   public ARIA_128CfbNoPaddingCipher() {
      super("aria-128-cfb", 16, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
