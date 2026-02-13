package net.glassless.provider.internal.cipher;

public class AES_192GcmPKCS5PaddingCipher extends AbstractCipher {
   public AES_192GcmPKCS5PaddingCipher() {
      super("aes-192-gcm", 24, CipherMode.GCM, CipherPadding.PKCS5PADDING);
   }
}
