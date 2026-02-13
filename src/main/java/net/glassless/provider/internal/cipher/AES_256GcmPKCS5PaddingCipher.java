package net.glassless.provider.internal.cipher;

public class AES_256GcmPKCS5PaddingCipher extends AbstractCipher {
   public AES_256GcmPKCS5PaddingCipher() {
      super("aes-256-gcm", 32, CipherMode.GCM, CipherPadding.PKCS5PADDING);
   }
}
