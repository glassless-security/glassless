package net.glassless.provider.internal.cipher;

public class AES_192WrapPadCipher extends AbstractCipher {
   public AES_192WrapPadCipher() {
      super("aes-192-wrap-pad", 24, CipherMode.KWP, CipherPadding.NOPADDING);
   }
}
