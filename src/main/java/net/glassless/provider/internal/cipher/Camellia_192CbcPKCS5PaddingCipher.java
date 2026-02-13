package net.glassless.provider.internal.cipher;

public class Camellia_192CbcPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_192CbcPKCS5PaddingCipher() {
      super("camellia-192-cbc", 24, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
