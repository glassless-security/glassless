package net.glassless.provider.internal.cipher;

public class AES_128GcmPKCS5PaddingCipher extends AbstractCipher {
   public AES_128GcmPKCS5PaddingCipher() {
      super("aes-128-gcm", 16, CipherMode.GCM, CipherPadding.PKCS5PADDING);
   }
}
