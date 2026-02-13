package net.glassless.provider.internal.cipher;

public class ARIA_256CfbPKCS5PaddingCipher extends AbstractCipher {
   public ARIA_256CfbPKCS5PaddingCipher() {
      super("aria-256-cfb", 32, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
