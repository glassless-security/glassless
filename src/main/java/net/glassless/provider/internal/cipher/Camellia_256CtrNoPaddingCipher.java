package net.glassless.provider.internal.cipher;

public class Camellia_256CtrNoPaddingCipher extends AbstractCipher {
   public Camellia_256CtrNoPaddingCipher() {
      super("camellia-256-ctr", CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
