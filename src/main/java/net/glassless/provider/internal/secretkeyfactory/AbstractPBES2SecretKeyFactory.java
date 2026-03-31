package net.glassless.provider.internal.secretkeyfactory;

import javax.crypto.SecretKey;

/**
 * Abstract SecretKeyFactory for PBES2 (Password-Based Encryption Scheme 2).
 * Combines PBKDF2 key derivation with a symmetric cipher (e.g., AES).
 * <p>
 * Extends {@link AbstractPBKDF2SecretKeyFactory} with a fixed key length
 * determined by the cipher and a custom {@link PBES2SecretKey} type.
 */
public abstract class AbstractPBES2SecretKeyFactory extends AbstractPBKDF2SecretKeyFactory {

   /**
    * Create a PBES2 SecretKeyFactory.
    *
    * @param algorithm     the algorithm name (e.g., "PBEWithHmacSHA256AndAES_128")
    * @param digestName    the HMAC digest name (e.g., "SHA256")
    * @param keyLengthBits the cipher key length in bits (e.g., 128 or 256)
    */
   protected AbstractPBES2SecretKeyFactory(String algorithm, String digestName, int keyLengthBits) {
      super(algorithm, digestName, keyLengthBits);
   }

   @Override
   protected SecretKey createKey(byte[] keyBytes) {
      return new PBES2SecretKey(keyBytes, algorithm);
   }

   /**
    * Internal PBES2 SecretKey implementation.
    */
   private static class PBES2SecretKey implements SecretKey {
      private static final long serialVersionUID = 1L;

      private final byte[] keyBytes;
      private final String algorithm;

      PBES2SecretKey(byte[] keyBytes, String algorithm) {
         this.keyBytes = keyBytes.clone();
         this.algorithm = algorithm;
      }

      @Override
      public String getAlgorithm() {
         return algorithm;
      }

      @Override
      public String getFormat() {
         return "RAW";
      }

      @Override
      public byte[] getEncoded() {
         return keyBytes.clone();
      }

      @Override
      public void destroy() {
         java.util.Arrays.fill(keyBytes, (byte) 0);
      }

      @Override
      public boolean isDestroyed() {
         for (byte b : keyBytes) {
            if (b != 0) return false;
         }
         return true;
      }
   }
}
