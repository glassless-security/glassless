package net.glassless.provider.internal.cipher;

public class AES_128GcmSivNoPaddingCipher extends AbstractCipher {
   public AES_128GcmSivNoPaddingCipher() {
      super("aes-128-gcm-siv", CipherMode.GCM_SIV, CipherPadding.NOPADDING);
   }
}
