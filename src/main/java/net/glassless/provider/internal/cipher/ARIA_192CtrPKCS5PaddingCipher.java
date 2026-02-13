package net.glassless.provider.internal.cipher;

public class ARIA_192CtrPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_192CtrPKCS5PaddingCipher() {
      super("aria-192-ctr", 24, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
