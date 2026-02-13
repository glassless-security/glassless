package net.glassless.provider.internal.cipher;

public class AES_192CcmNoPaddingCipher extends AbstractCipher {
   public AES_192CcmNoPaddingCipher() {
      super("aes-192-ccm", 24, CipherMode.CCM, CipherPadding.NOPADDING);
   }
}
