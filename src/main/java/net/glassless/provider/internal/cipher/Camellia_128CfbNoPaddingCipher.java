package net.glassless.provider.internal.cipher;

public class Camellia_128CfbNoPaddingCipher extends AbstractCipher {
   public Camellia_128CfbNoPaddingCipher() {
      super("camellia-128-cfb", 16, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
