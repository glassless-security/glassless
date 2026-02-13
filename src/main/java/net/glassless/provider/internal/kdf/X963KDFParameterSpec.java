package net.glassless.provider.internal.kdf;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Parameter specification for ANSI X9.63 Key Derivation Function.
 *
 * X9.63 KDF is commonly used with ECDH key agreement to derive
 * symmetric keys from shared secrets.
 */
public class X963KDFParameterSpec implements AlgorithmParameterSpec {

   private final byte[] sharedSecret;
   private final byte[] sharedInfo;
   private final int keyLength;

   /**
    * Creates an X963KDFParameterSpec.
    *
    * @param sharedSecret the shared secret (e.g., from ECDH)
    * @param sharedInfo optional shared info (can be null)
    * @param keyLength the desired key length in bytes
    */
   public X963KDFParameterSpec(byte[] sharedSecret, byte[] sharedInfo, int keyLength) {
      if (sharedSecret == null || sharedSecret.length == 0) {
         throw new IllegalArgumentException("Shared secret cannot be null or empty");
      }
      if (keyLength <= 0) {
         throw new IllegalArgumentException("Key length must be positive");
      }

      this.sharedSecret = sharedSecret.clone();
      this.sharedInfo = sharedInfo != null ? sharedInfo.clone() : null;
      this.keyLength = keyLength;
   }

   public byte[] getSharedSecret() {
      return sharedSecret.clone();
   }

   public byte[] getSharedInfo() {
      return sharedInfo != null ? sharedInfo.clone() : null;
   }

   public int getKeyLength() {
      return keyLength;
   }

   /**
    * Clears sensitive data from memory.
    */
   public void clear() {
      Arrays.fill(sharedSecret, (byte) 0);
   }
}
