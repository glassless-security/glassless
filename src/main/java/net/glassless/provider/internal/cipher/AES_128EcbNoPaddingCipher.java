package net.glassless.provider.internal.cipher;

public class AES_128EcbNoPaddingCipher extends AbstractCipher {
   public AES_128EcbNoPaddingCipher() {
      super("aes-128-ecb", 16, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
