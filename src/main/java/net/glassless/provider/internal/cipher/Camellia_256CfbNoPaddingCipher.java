package net.glassless.provider.internal.cipher;

public class Camellia_256CfbNoPaddingCipher extends AbstractCipher {
   public Camellia_256CfbNoPaddingCipher() {
      super("camellia-256-cfb", CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
