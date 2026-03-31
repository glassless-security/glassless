package net.glassless.provider.internal.cipher;

public class Camellia_192OfbNoPaddingCipher extends AbstractCipher {
   public Camellia_192OfbNoPaddingCipher() {
      super("camellia-192-ofb", CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
