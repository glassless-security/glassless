package net.glassless.provider.internal.cipher;

public class AES_192GcmSivNoPaddingCipher extends AbstractCipher {
   public AES_192GcmSivNoPaddingCipher() {
      super("aes-192-gcm-siv", CipherMode.GCM_SIV, CipherPadding.NOPADDING);
   }
}
