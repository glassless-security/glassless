package net.glassless.provider.internal.cipher;

public class Camellia_192OfbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_192OfbPKCS5PaddingCipher() {
      super("camellia-192-ofb", 24, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
