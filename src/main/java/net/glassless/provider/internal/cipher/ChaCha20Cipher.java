package net.glassless.provider.internal.cipher;

public class ChaCha20Cipher extends AbstractCipher {
   public ChaCha20Cipher() {
      super("chacha20", 32, CipherMode.STREAM, CipherPadding.NOPADDING);
   }
}
