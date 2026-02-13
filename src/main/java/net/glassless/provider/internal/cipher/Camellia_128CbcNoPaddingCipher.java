package net.glassless.provider.internal.cipher;

public class Camellia_128CbcNoPaddingCipher extends AbstractCipher {
   public Camellia_128CbcNoPaddingCipher() {
      super("camellia-128-cbc", 16, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
