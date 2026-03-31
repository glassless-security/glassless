package net.glassless.provider.internal.cipher;

public class AES_256CbcNoPaddingCipher extends AbstractCipher {
   public AES_256CbcNoPaddingCipher() {
      super("aes-256-cbc", CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
