package net.glassless.provider.internal.cipher;

public class Camellia_128CtrPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_128CtrPKCS5PaddingCipher() {
      super("camellia-128-ctr", 16, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
