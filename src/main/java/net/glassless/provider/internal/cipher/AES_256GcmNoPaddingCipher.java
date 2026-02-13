package net.glassless.provider.internal.cipher;

public class AES_256GcmNoPaddingCipher extends AbstractCipher {
   public AES_256GcmNoPaddingCipher() {
      super("aes-256-gcm", 32, CipherMode.GCM, CipherPadding.NOPADDING);
   }
}
