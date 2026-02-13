package net.glassless.provider.internal.cipher;

public class Camellia_256EcbNoPaddingCipher extends AbstractCipher {
   public Camellia_256EcbNoPaddingCipher() {
      super("camellia-256-ecb", 32, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
