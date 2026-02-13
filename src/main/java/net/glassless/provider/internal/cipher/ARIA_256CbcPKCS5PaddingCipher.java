package net.glassless.provider.internal.cipher;

public class ARIA_256CbcPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_256CbcPKCS5PaddingCipher() {
      super("aria-256-cbc", 32, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
