package net.glassless.provider.internal.cipher;

public class AES_128WrapPadCipher extends AbstractCipher {
   public AES_128WrapPadCipher() {
      super("aes-128-wrap-pad", 16, CipherMode.KWP, CipherPadding.NOPADDING);
   }
}
