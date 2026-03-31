package net.glassless.provider.internal.cipher;

public class Camellia_192CtrPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_192CtrPKCS5PaddingCipher() {
      super("camellia-192-ctr", CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
