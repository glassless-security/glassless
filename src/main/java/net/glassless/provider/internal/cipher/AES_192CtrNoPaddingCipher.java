package net.glassless.provider.internal.cipher;

public class AES_192CtrNoPaddingCipher extends AbstractCipher {
   public AES_192CtrNoPaddingCipher() {
      super("aes-192-ctr", 24, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
