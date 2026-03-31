package net.glassless.provider.internal.cipher;

public class AES_192OfbNoPaddingCipher extends AbstractCipher {
   public AES_192OfbNoPaddingCipher() {
      super("aes-192-ofb", CipherMode.OFB, CipherPadding.NOPADDING);
   }
}
