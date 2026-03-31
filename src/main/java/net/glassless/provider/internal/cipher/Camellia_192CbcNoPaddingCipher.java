package net.glassless.provider.internal.cipher;

public class Camellia_192CbcNoPaddingCipher extends AbstractCipher {
   public Camellia_192CbcNoPaddingCipher() {
      super("camellia-192-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
