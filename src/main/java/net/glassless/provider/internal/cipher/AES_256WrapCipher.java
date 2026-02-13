package net.glassless.provider.internal.cipher;

public class AES_256WrapCipher extends AbstractCipher {
   public AES_256WrapCipher() {
      super("aes-256-wrap", 32, CipherMode.KW, CipherPadding.NOPADDING);
   }
}
