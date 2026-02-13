package net.glassless.provider.internal.cipher;

public class ARIA_256GcmPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_256GcmPKCS5PaddingCipher() {
      super("aria-256-gcm", 32, CipherMode.GCM, CipherPadding.PKCS5PADDING);
   }
}
