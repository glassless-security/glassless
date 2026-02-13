package net.glassless.provider.internal.cipher;

public class AES_128CfbNoPaddingCipher extends AbstractCipher {
   public AES_128CfbNoPaddingCipher() {
      super("aes-128-cfb", 16, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
