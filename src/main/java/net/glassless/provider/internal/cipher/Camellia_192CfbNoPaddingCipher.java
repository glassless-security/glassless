package net.glassless.provider.internal.cipher;

public class Camellia_192CfbNoPaddingCipher extends AbstractCipher {
   public Camellia_192CfbNoPaddingCipher() {
      super("camellia-192-cfb", 24, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
