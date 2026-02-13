package net.glassless.provider.internal.cipher;

public class AES_192CbcNoPaddingCipher extends AbstractCipher {
   public AES_192CbcNoPaddingCipher() {
      super("aes-192-cbc", 24, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
