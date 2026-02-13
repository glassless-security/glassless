package net.glassless.provider.internal.cipher;

public class ARIA_192GcmPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_192GcmPKCS5PaddingCipher() {
      super("aria-192-gcm", 24, CipherMode.GCM, CipherPadding.PKCS5PADDING);
   }
}
