package net.glassless.provider.internal.secretkeyfactory;

import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Key specification for Argon2 key derivation.
 *
 * Argon2 parameters:
 * - password: the password
 * - salt: the salt (should be at least 16 bytes)
 * - iterations: number of iterations (t_cost), minimum 1
 * - memoryKB: memory in KB (m_cost), minimum 8
 * - parallelism: parallelism (lanes), minimum 1
 * - keyLength: desired key length in bits
 * - ad: optional associated data
 * - secret: optional secret value
 */
public class Argon2KeySpec implements KeySpec {

   private final char[] password;
   private final byte[] salt;
   private final int iterations;
   private final int memoryKB;
   private final int parallelism;
   private final int keyLength;
   private final byte[] associatedData;
   private final byte[] secret;

   /**
    * Creates an Argon2KeySpec with all parameters.
    *
    * @param password the password
    * @param salt the salt (recommended at least 16 bytes)
    * @param iterations number of iterations (t_cost), minimum 1
    * @param memoryKB memory in KB (m_cost), minimum 8
    * @param parallelism number of lanes/threads, minimum 1
    * @param keyLength desired key length in bits
    * @param associatedData optional associated data (can be null)
    * @param secret optional secret (can be null)
    */
   public Argon2KeySpec(char[] password, byte[] salt, int iterations, int memoryKB,
         int parallelism, int keyLength, byte[] associatedData, byte[] secret) {
      if (password == null) {
         throw new IllegalArgumentException("Password cannot be null");
      }
      if (salt == null || salt.length < 8) {
         throw new IllegalArgumentException("Salt must be at least 8 bytes");
      }
      if (iterations < 1) {
         throw new IllegalArgumentException("Iterations must be >= 1");
      }
      if (memoryKB < 8) {
         throw new IllegalArgumentException("Memory must be >= 8 KB");
      }
      if (parallelism < 1) {
         throw new IllegalArgumentException("Parallelism must be >= 1");
      }
      if (keyLength <= 0) {
         throw new IllegalArgumentException("Key length must be positive");
      }

      this.password = password.clone();
      this.salt = salt.clone();
      this.iterations = iterations;
      this.memoryKB = memoryKB;
      this.parallelism = parallelism;
      this.keyLength = keyLength;
      this.associatedData = associatedData != null ? associatedData.clone() : null;
      this.secret = secret != null ? secret.clone() : null;
   }

   /**
    * Creates an Argon2KeySpec with common defaults.
    *
    * @param password the password
    * @param salt the salt
    * @param iterations number of iterations
    * @param memoryKB memory in KB
    * @param parallelism number of lanes
    * @param keyLength desired key length in bits
    */
   public Argon2KeySpec(char[] password, byte[] salt, int iterations, int memoryKB,
         int parallelism, int keyLength) {
      this(password, salt, iterations, memoryKB, parallelism, keyLength, null, null);
   }

   public char[] getPassword() {
      return password.clone();
   }

   public byte[] getSalt() {
      return salt.clone();
   }

   public int getIterations() {
      return iterations;
   }

   public int getMemoryKB() {
      return memoryKB;
   }

   public int getParallelism() {
      return parallelism;
   }

   public int getKeyLength() {
      return keyLength;
   }

   public byte[] getAssociatedData() {
      return associatedData != null ? associatedData.clone() : null;
   }

   public byte[] getSecret() {
      return secret != null ? secret.clone() : null;
   }

   /**
    * Clears sensitive data from memory.
    */
   public void clear() {
      Arrays.fill(password, '\0');
      if (secret != null) {
         Arrays.fill(secret, (byte) 0);
      }
   }
}
