package net.glassless.provider.internal.cipher;

public class AES_192EcbNoPaddingCipher extends AbstractCipher {
   public AES_192EcbNoPaddingCipher() {
      super("aes-192-ecb", 24, CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
