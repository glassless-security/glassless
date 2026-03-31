package net.glassless.provider.internal.cipher;

public class AES_256GcmSivNoPaddingCipher extends AbstractCipher {
   public AES_256GcmSivNoPaddingCipher() {
      super("aes-256-gcm-siv", CipherMode.GCM_SIV, CipherPadding.NOPADDING);
   }
}
