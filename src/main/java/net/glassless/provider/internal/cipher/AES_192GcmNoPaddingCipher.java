package net.glassless.provider.internal.cipher;

public class AES_192GcmNoPaddingCipher extends AbstractCipher {
   public AES_192GcmNoPaddingCipher() {
      super("aes-192-gcm", 24, CipherMode.GCM, CipherPadding.NOPADDING);
   }
}
