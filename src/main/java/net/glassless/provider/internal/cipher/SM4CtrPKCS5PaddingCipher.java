package net.glassless.provider.internal.cipher;

public class SM4CtrPKCS5PaddingCipher extends AbstractCipher {
   public SM4CtrPKCS5PaddingCipher() {
      super("sm4-ctr", 16, CipherMode.CTR, CipherPadding.PKCS5PADDING);
   }
}
