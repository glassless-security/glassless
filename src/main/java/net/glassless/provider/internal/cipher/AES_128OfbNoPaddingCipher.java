package net.glassless.provider.internal.cipher;

public class AES_128OfbNoPaddingCipher extends AbstractCipher {
   public AES_128OfbNoPaddingCipher() {
      super("aes-128-ofb", 16, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
