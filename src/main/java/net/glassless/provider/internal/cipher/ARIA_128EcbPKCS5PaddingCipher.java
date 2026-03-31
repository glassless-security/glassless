package net.glassless.provider.internal.cipher;

public class ARIA_128EcbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128EcbPKCS5PaddingCipher() {
      super("aria-128-ecb", CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
