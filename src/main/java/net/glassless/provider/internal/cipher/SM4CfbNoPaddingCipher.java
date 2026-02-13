package net.glassless.provider.internal.cipher;

public class SM4CfbNoPaddingCipher extends AbstractCipher {
   public SM4CfbNoPaddingCipher() {
      super("sm4-cfb", 16, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
