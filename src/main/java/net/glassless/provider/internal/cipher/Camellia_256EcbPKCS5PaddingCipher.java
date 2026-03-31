package net.glassless.provider.internal.cipher;

public class Camellia_256EcbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_256EcbPKCS5PaddingCipher() {
      super("camellia-256-ecb", CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
