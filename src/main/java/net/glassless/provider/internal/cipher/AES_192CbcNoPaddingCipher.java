package net.glassless.provider.internal.cipher;

public class AES_192CbcNoPaddingCipher extends AbstractCipher {
   public AES_192CbcNoPaddingCipher() {
      super("aes-192-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
