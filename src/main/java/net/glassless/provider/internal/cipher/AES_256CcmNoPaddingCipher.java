package net.glassless.provider.internal.cipher;

public class AES_256CcmNoPaddingCipher extends AbstractCipher {
   public AES_256CcmNoPaddingCipher() {
      super("aes-256-ccm", 32, CipherMode.CCM, CipherPadding.NOPADDING);
   }
}
