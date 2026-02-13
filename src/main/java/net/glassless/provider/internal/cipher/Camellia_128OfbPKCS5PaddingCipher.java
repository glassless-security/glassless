package net.glassless.provider.internal.cipher;

public class Camellia_128OfbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_128OfbPKCS5PaddingCipher() {
      super("camellia-128-ofb", 16, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
