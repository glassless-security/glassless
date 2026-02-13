package net.glassless.provider.internal.cipher;

public class ARIA_192GcmNoPaddingCipher extends AbstractCipher {
   public ARIA_192GcmNoPaddingCipher() {
      super("aria-192-gcm", 24, CipherMode.GCM, CipherPadding.NOPADDING);
   }
}
