package net.glassless.provider.internal.cipher;

import java.security.InvalidKeyException;
import java.security.Key;

/**
 * Generic AES Key Wrap cipher that determines the OpenSSL algorithm name from the key size
 * at init time. This allows using standard JCA names like "AESWrap" and "AESWrapPad"
 * without specifying the key size upfront.
 */
public class AESWrapCipher extends AbstractCipher {

   private final String opensslModeName;

   protected AESWrapCipher(String opensslModeName, CipherMode mode) {
      super(null, mode, CipherPadding.NOPADDING);
      this.opensslModeName = opensslModeName;
   }

   @Override
   protected void resolveAlgorithm(Key key) throws InvalidKeyException {
      if (key == null) {
         throw new InvalidKeyException("Key must not be null");
      }
      byte[] encoded = key.getEncoded();
      if (encoded == null) {
         throw new InvalidKeyException("Key encoding must not be null");
      }
      int keySizeBits = encoded.length * 8;
      String keySize = switch (keySizeBits) {
         case 128 -> "128";
         case 192 -> "192";
         case 256 -> "256";
         default -> throw new InvalidKeyException(
            "Unsupported AES key size: " + keySizeBits + " bits. Supported: 128, 192, 256");
      };
      setAlgorithmName("aes-" + keySize + "-" + opensslModeName);
   }

   public static class Wrap extends AESWrapCipher {
      public Wrap() { super("wrap", CipherMode.KW); }
   }

   public static class WrapPad extends AESWrapCipher {
      public WrapPad() { super("wrap-pad", CipherMode.KWP); }
   }
}
