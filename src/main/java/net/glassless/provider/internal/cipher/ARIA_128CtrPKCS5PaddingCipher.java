package net.glassless.provider.internal.cipher;

public class ARIA_128CtrPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128CtrPKCS5PaddingCipher() {
      super("aria-128-ctr", 16, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
