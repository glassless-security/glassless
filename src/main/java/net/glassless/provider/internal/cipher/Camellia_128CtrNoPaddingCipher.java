package net.glassless.provider.internal.cipher;

public class Camellia_128CtrNoPaddingCipher extends AbstractCipher {
   public Camellia_128CtrNoPaddingCipher() {
      super("camellia-128-ctr", 16, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
