package net.glassless.provider.internal.cipher;

public class Camellia_256OfbPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_256OfbPKCS5PaddingCipher() {
      super("camellia-256-ofb", 32, CipherMode.OFB, CipherPadding.PKCS5PADDING);
   }
}
