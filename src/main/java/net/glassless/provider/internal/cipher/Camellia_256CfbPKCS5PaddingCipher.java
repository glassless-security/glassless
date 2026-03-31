package net.glassless.provider.internal.cipher;

public class Camellia_256CfbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_256CfbPKCS5PaddingCipher() {
      super("camellia-256-cfb", CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
