package net.glassless.provider.internal.cipher;

public class SM4CtrNoPaddingCipher extends AbstractCipher {
   public SM4CtrNoPaddingCipher() {
      super("sm4-ctr", 16, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
