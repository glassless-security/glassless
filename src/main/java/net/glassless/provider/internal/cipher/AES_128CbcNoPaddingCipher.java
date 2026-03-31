package net.glassless.provider.internal.cipher;

public class AES_128CbcNoPaddingCipher extends AbstractCipher {
   public AES_128CbcNoPaddingCipher() {
      super("aes-128-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
