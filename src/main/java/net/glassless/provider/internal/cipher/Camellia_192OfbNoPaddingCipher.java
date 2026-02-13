package net.glassless.provider.internal.cipher;

public class Camellia_192OfbNoPaddingCipher extends AbstractCipher {
   public Camellia_192OfbNoPaddingCipher() {
      super("camellia-192-ofb", 24, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
