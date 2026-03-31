package net.glassless.provider.internal.cipher;

public class AES_128WrapCipher extends AbstractCipher {
   public AES_128WrapCipher() {
      super("aes-128-wrap", CipherMode.KW, CipherPadding.NOPADDING);
   }
}
