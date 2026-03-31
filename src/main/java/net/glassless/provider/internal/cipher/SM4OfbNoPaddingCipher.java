package net.glassless.provider.internal.cipher;

public class SM4OfbNoPaddingCipher extends AbstractCipher {
   public SM4OfbNoPaddingCipher() {
      super("sm4-ofb", CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
