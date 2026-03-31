package net.glassless.provider.internal.cipher;

public class DESedeCbcNoPaddingCipher extends AbstractCipher {
   public DESedeCbcNoPaddingCipher() {
      super("des-ede3-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
