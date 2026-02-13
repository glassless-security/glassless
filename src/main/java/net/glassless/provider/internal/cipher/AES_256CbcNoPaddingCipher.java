package net.glassless.provider.internal.cipher;

public class AES_256CbcNoPaddingCipher extends AbstractCipher {
   public AES_256CbcNoPaddingCipher() {
      super("aes-256-cbc", 32, CipherMode.CBC, CipherPadding.NOPADDING);
   }
}
