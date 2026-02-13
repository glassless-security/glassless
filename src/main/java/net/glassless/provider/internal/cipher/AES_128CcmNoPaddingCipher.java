package net.glassless.provider.internal.cipher;

public class AES_128CcmNoPaddingCipher extends AbstractCipher {
   public AES_128CcmNoPaddingCipher() {
      super("aes-128-ccm", 16, CipherMode.CCM, CipherPadding.NOPADDING);
   }
}
