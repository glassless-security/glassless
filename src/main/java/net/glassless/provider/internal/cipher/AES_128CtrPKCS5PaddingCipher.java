package net.glassless.provider.internal.cipher;

public class AES_128CtrPKCS5PaddingCipher extends AbstractCipher {
   public AES_128CtrPKCS5PaddingCipher() {
      super("aes-128-ctr", 16, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
