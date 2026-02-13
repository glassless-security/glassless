package net.glassless.provider.internal.cipher;

public class SM4EcbNoPaddingCipher extends AbstractCipher {
   public SM4EcbNoPaddingCipher() {
      super("sm4-ecb", 16, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
