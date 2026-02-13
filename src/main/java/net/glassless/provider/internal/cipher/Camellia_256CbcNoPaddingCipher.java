package net.glassless.provider.internal.cipher;

public class Camellia_256CbcNoPaddingCipher extends AbstractCipher {
   public Camellia_256CbcNoPaddingCipher() {
      super("camellia-256-cbc", 32, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
