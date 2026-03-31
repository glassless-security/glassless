package net.glassless.provider.internal.cipher;

public class SM4CbcNoPaddingCipher extends AbstractCipher {
   public SM4CbcNoPaddingCipher() {
      super("sm4-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
