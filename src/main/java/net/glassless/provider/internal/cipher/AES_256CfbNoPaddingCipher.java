package net.glassless.provider.internal.cipher;

public class AES_256CfbNoPaddingCipher extends AbstractCipher {
   public AES_256CfbNoPaddingCipher() {
      super("aes-256-cfb", 32, CipherMode.CFB, CipherPadding.NOPADDING);
   }
}
