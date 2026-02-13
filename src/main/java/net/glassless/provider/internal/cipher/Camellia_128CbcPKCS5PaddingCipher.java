package net.glassless.provider.internal.cipher;

public class Camellia_128CbcPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_128CbcPKCS5PaddingCipher() {
      super("camellia-128-cbc", 16, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
