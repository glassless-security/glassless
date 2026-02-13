package net.glassless.provider.internal.cipher;

public class Camellia_192EcbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_192EcbPKCS5PaddingCipher() {
      super("camellia-192-ecb", 24, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
