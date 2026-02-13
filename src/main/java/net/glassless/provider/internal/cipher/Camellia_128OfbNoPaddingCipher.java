package net.glassless.provider.internal.cipher;

public class Camellia_128OfbNoPaddingCipher extends AbstractCipher {
   public Camellia_128OfbNoPaddingCipher() {
      super("camellia-128-ofb", 16, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
