package net.glassless.provider.internal.cipher;

public class AES_128GcmNoPaddingCipher extends AbstractCipher {
   public AES_128GcmNoPaddingCipher() {
      super("aes-128-gcm", 16, CipherMode.GCM, CipherPadding.NOPADDING);
   }
}
