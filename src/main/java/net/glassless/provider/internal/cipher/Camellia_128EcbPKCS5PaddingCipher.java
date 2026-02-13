package net.glassless.provider.internal.cipher;

public class Camellia_128EcbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_128EcbPKCS5PaddingCipher() {
      super("camellia-128-ecb", 16, CipherMode.ECB, CipherPadding.PKCS5PADDING);
   }
}
