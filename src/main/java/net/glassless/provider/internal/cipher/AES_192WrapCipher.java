package net.glassless.provider.internal.cipher;

public class AES_192WrapCipher extends AbstractCipher {
   public AES_192WrapCipher() {
      super("aes-192-wrap", 24, CipherMode.KW, CipherPadding.NOPADDING);
   }
}
