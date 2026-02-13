package net.glassless.provider.internal.cipher;

public class ARIA_128GcmNoPaddingCipher extends AbstractCipher {
   public ARIA_128GcmNoPaddingCipher() {
      super("aria-128-gcm", 16, CipherMode.GCM, CipherPadding.NOPADDING);
   }
}
