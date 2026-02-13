package net.glassless.provider.internal.cipher;

public class Camellia_256CtrPKCS5PaddingCipher extends AbstractCipher {
   public Camellia_256CtrPKCS5PaddingCipher() {
      super("camellia-256-ctr", 32, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
