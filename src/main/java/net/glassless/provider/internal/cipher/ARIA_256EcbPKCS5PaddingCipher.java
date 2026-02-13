package net.glassless.provider.internal.cipher;

public class ARIA_256EcbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_256EcbPKCS5PaddingCipher() {
      super("aria-256-ecb", 32, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
