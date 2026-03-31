package net.glassless.provider.internal.cipher;

public class Camellia_256OfbNoPaddingCipher extends AbstractCipher {
   public Camellia_256OfbNoPaddingCipher() {
      super("camellia-256-ofb", CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
