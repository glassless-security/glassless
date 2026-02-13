package net.glassless.provider.internal.cipher;

public class AES_128CtrNoPaddingCipher extends AbstractCipher {
   public AES_128CtrNoPaddingCipher() {
      super("aes-128-ctr", 16, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
