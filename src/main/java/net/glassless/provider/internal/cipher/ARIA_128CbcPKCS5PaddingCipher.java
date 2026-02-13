package net.glassless.provider.internal.cipher;

public class ARIA_128CbcPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128CbcPKCS5PaddingCipher() {
      super("aria-128-cbc", 16, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
