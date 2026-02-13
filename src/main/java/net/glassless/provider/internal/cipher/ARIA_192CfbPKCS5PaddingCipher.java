package net.glassless.provider.internal.cipher;

public class ARIA_192CfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_192CfbPKCS5PaddingCipher() {
      super("aria-192-cfb", 24, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
