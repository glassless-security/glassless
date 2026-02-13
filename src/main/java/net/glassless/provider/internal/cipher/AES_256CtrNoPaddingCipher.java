package net.glassless.provider.internal.cipher;

public class AES_256CtrNoPaddingCipher extends AbstractCipher {
   public AES_256CtrNoPaddingCipher() {
      super("aes-256-ctr", 32, CipherMode.CTR, CipherPadding.NOPADDING);
   }
}
