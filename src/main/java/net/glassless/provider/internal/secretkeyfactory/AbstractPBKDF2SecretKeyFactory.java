package net.glassless.provider.internal.secretkeyfactory;

import java.lang.foreign.Arena;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract SecretKeyFactory for PBKDF2 key derivation using OpenSSL.
 */
public abstract class AbstractPBKDF2SecretKeyFactory extends AbstractSecretKeyFactory {

   /**
    * Password encoding scheme for PBKDF2.
    */
   public enum PasswordEncoding {
      /**
       * UTF-8 encoding (default)
       */
      UTF8,
      /**
       * 8-bit encoding - lower 8 bits of each char
       */
      EIGHT_BIT
   }

   private final String digestName;
   private final int defaultKeyLength; // in bits
   private final PasswordEncoding encoding;

   protected AbstractPBKDF2SecretKeyFactory(String algorithm, String digestName, int defaultKeyLength) {
      this(algorithm, digestName, defaultKeyLength, PasswordEncoding.UTF8);
   }

   protected AbstractPBKDF2SecretKeyFactory(String algorithm, String digestName, int defaultKeyLength, PasswordEncoding encoding) {
      super(algorithm);
      this.digestName = digestName;
      this.defaultKeyLength = defaultKeyLength;
      this.encoding = encoding;
   }

   @Override
   protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
      if (!(keySpec instanceof PBEKeySpec pbeKeySpec)) {
         throw new InvalidKeySpecException("KeySpec must be a PBEKeySpec");
      }

      char[] password = pbeKeySpec.getPassword();
      if (password == null) {
         throw new InvalidKeySpecException("Password cannot be null");
      }

      byte[] salt = pbeKeySpec.getSalt();
      if (salt == null) {
         throw new InvalidKeySpecException("Salt cannot be null");
      }

      int iterationCount = pbeKeySpec.getIterationCount();
      if (iterationCount <= 0) {
         throw new InvalidKeySpecException("Iteration count must be positive");
      }

      int keyLength = pbeKeySpec.getKeyLength();
      if (keyLength <= 0) {
         keyLength = defaultKeyLength;
      }

      try (Arena arena = Arena.ofConfined()) {
         byte[] passwordBytes = encodePassword(password);

         try {
            byte[] derivedKey = OpenSSLCrypto.PKCS5_PBKDF2_HMAC(
               passwordBytes, salt, iterationCount, digestName, keyLength / 8, arena);

            return createKey(derivedKey);
         } finally {
            java.util.Arrays.fill(passwordBytes, (byte) 0);
         }

      } catch (Throwable e) {
         throw new ProviderException("Error deriving key with PBKDF2", e);
      }
   }

   /**
    * Encode the password according to the configured encoding scheme.
    */
   private byte[] encodePassword(char[] password) {
      if (encoding == PasswordEncoding.EIGHT_BIT) {
         byte[] result = new byte[password.length];
         for (int i = 0; i < password.length; i++) {
            result[i] = (byte) (password[i] & 0xFF);
         }
         return result;
      } else {
         return new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);
      }
   }
}
