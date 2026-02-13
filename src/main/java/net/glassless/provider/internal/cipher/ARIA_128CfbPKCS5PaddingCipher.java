package net.glassless.provider.internal.cipher;

public class ARIA_128CfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_128CfbPKCS5PaddingCipher() {
      super("aria-128-cfb", 16, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
