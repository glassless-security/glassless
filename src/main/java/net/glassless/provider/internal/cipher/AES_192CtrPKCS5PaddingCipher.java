package net.glassless.provider.internal.cipher;

public class AES_192CtrPKCS5PaddingCipher extends AbstractCipher {
   public AES_192CtrPKCS5PaddingCipher() {
      super("aes-192-ctr", 24, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
