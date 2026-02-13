package net.glassless.provider.internal.cipher;

public class Camellia_192EcbNoPaddingCipher extends AbstractCipher {
   public Camellia_192EcbNoPaddingCipher() {
      super("camellia-192-ecb", 24, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
