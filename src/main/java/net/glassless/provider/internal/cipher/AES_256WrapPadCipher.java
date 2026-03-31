package net.glassless.provider.internal.cipher;

public class AES_256WrapPadCipher extends AbstractCipher {
   public AES_256WrapPadCipher() {
      super("aes-256-wrap-pad", CipherMode.KWP, CipherPadding.NOPADDING);
   }
}
