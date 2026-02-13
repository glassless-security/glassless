package net.glassless.provider.internal.cipher;

public class ARIA_256GcmNoPaddingCipher extends AbstractCipher {
   public ARIA_256GcmNoPaddingCipher() {
      super("aria-256-gcm", 32, CipherMode.GCM, CipherPadding.NOPADDING);
   }
}
