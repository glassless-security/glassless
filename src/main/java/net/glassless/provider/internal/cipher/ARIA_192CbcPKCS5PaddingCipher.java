package net.glassless.provider.internal.cipher;

public class ARIA_192CbcPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_192CbcPKCS5PaddingCipher() {
      super("aria-192-cbc", CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
