package net.glassless.provider.internal.cipher;

public class ARIA_256CtrPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_256CtrPKCS5PaddingCipher() {
      super("aria-256-ctr", 32, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
