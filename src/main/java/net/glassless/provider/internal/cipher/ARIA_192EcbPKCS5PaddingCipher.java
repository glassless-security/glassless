package net.glassless.provider.internal.cipher;

public class ARIA_192EcbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_192EcbPKCS5PaddingCipher() {
      super("aria-192-ecb", 24, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
