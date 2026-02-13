package net.glassless.provider.internal.cipher;

public class AES_256CtrPKCS5PaddingCipher extends AbstractCipher {
   public AES_256CtrPKCS5PaddingCipher() {
      super("aes-256-ctr", 32, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
