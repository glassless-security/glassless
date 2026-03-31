package net.glassless.provider.internal.cipher;

public class AES_192CfbNoPaddingCipher extends AbstractCipher {
   public AES_192CfbNoPaddingCipher() {
      super("aes-192-cfb", CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
