package net.glassless.provider.internal.cipher;

public class AES_256XtsNoPaddingCipher extends AbstractCipher {
   public AES_256XtsNoPaddingCipher() {
      // XTS uses double the key size (256-bit AES-XTS uses 512-bit key)
      super("aes-256-xts", 64, CipherMode.XTS, CipherPadding.NOPADDING);
   }
}
