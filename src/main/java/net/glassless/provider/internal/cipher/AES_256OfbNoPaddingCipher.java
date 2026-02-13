package net.glassless.provider.internal.cipher;

public class AES_256OfbNoPaddingCipher extends AbstractCipher {
   public AES_256OfbNoPaddingCipher() {
      super("aes-256-ofb", 32, CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
