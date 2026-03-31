package net.glassless.provider.internal.cipher;

public class Camellia_192CtrNoPaddingCipher extends AbstractCipher {
   public Camellia_192CtrNoPaddingCipher() {
      super("camellia-192-ctr", CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
