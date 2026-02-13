package net.glassless.provider.internal.cipher;

public class ARIA_128GcmPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128GcmPKCS5PaddingCipher() {
      super("aria-128-gcm", 16, CipherMode.GCM, CipherPadding.PKCS5PADDING);
   }
}
