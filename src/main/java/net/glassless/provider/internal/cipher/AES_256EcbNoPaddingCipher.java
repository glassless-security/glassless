package net.glassless.provider.internal.cipher;

public class AES_256EcbNoPaddingCipher extends AbstractCipher {
   public AES_256EcbNoPaddingCipher() {
      super("aes-256-ecb", CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
