package net.glassless.provider.internal.cipher;

public class Camellia_256CbcPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_256CbcPKCS5PaddingCipher() {
      super("camellia-256-cbc", 32, CipherMode.CBC, CipherPadding.PKCS5PADDING);
   }
}
