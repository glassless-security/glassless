package net.glassless.provider.internal.cipher;

public class AES_128XtsNoPaddingCipher extends AbstractCipher {
   public AES_128XtsNoPaddingCipher() {
      // XTS uses double the key size (128-bit AES-XTS uses 256-bit key)
      super("aes-128-xts", 32, CipherMode.XTS, CipherPadding.NOPADDING);
   }
}
