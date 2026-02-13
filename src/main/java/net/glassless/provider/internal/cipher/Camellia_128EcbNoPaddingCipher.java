package net.glassless.provider.internal.cipher;

public class Camellia_128EcbNoPaddingCipher extends AbstractCipher {
   public Camellia_128EcbNoPaddingCipher() {
      super("camellia-128-ecb", 16, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
