package net.glassless.provider.internal.cipher;

public class Camellia_128CfbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_128CfbPKCS5PaddingCipher() {
      super("camellia-128-cfb", 16, CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
