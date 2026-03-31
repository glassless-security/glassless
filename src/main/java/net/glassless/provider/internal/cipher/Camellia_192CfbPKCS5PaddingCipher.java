package net.glassless.provider.internal.cipher;

public class Camellia_192CfbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_192CfbPKCS5PaddingCipher() {
      super("camellia-192-cfb", CipherMode.CFB, CipherPadding.PKCS5PADDING);
   }
}
