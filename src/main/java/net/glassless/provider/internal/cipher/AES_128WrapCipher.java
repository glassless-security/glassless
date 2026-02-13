package net.glassless.provider.internal.cipher;

public class AES_128WrapCipher extends AbstractCipher {
   public AES_128WrapCipher() {
      super("aes-128-wrap", 16, CipherMode.KW, CipherPadding.NOPADDING);
   }
}
