package net.glassless.provider.internal.secretkeyfactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for Argon2 SecretKeyFactory implementations.
 *
 * Argon2 is a password hashing algorithm that was the winner of the
 * Password Hashing Competition (PHC). It comes in three variants:
 * - Argon2d: Data-dependent, faster, more resistant to GPU attacks
 * - Argon2i: Data-independent, more resistant to side-channel attacks
 * - Argon2id: Hybrid of Argon2d and Argon2i (recommended)
 *
 * Requires OpenSSL 3.2 or later.
 */
public abstract class AbstractArgon2SecretKeyFactory extends SecretKeyFactorySpi {

   private final String algorithm;
   private final String kdfName;

   protected AbstractArgon2SecretKeyFactory(String algorithm, String kdfName) {
      this.algorithm = algorithm;
      this.kdfName = kdfName;
   }

   @Override
   protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
      if (!(keySpec instanceof Argon2KeySpec)) {
         throw new InvalidKeySpecException("KeySpec must be an Argon2KeySpec");
      }

      Argon2KeySpec argon2Spec = (Argon2KeySpec) keySpec;

      char[] password = argon2Spec.getPassword();
      byte[] salt = argon2Spec.getSalt();
      int iterations = argon2Spec.getIterations();
      int memoryKB = argon2Spec.getMemoryKB();
      int parallelism = argon2Spec.getParallelism();
      int keyLengthBits = argon2Spec.getKeyLength();
      int keyLengthBytes = keyLengthBits / 8;
      byte[] ad = argon2Spec.getAssociatedData();
      byte[] secret = argon2Spec.getSecret();

      try (Arena arena = Arena.ofConfined()) {
         // Convert password to bytes (UTF-8)
         byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);

         try {
            // Fetch the Argon2 KDF
            MemorySegment kdf = OpenSSLCrypto.EVP_KDF_fetch(MemorySegment.NULL, kdfName, MemorySegment.NULL, arena);
            if (kdf == null || kdf.address() == 0) {
               throw new ProviderException("Failed to fetch " + kdfName + " KDF. Requires OpenSSL 3.2+");
            }

            try {
               // Create KDF context
               MemorySegment ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
               if (ctx == null || ctx.address() == 0) {
                  throw new ProviderException("Failed to create " + kdfName + " context");
               }

               try {
                  // Create Argon2 parameters
                  MemorySegment osslParams = OpenSSLCrypto.createArgon2Params(
                     passwordBytes, salt, iterations, memoryKB, parallelism, ad, secret, arena
                  );

                  // Allocate output buffer
                  MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, keyLengthBytes);

                  // Derive the key
                  int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, keyLengthBytes, osslParams);
                  if (result != 1) {
                     throw new ProviderException(kdfName + " key derivation failed");
                  }

                  // Extract the derived key
                  byte[] derivedKey = new byte[keyLengthBytes];
                  output.asByteBuffer().get(derivedKey);

                  return new SecretKeySpec(derivedKey, algorithm);
               } finally {
                  OpenSSLCrypto.EVP_KDF_CTX_free(ctx);
               }
            } finally {
               OpenSSLCrypto.EVP_KDF_free(kdf);
            }
         } finally {
            // Clear sensitive data
            Arrays.fill(passwordBytes, (byte) 0);
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error deriving key with " + kdfName, e);
      }
   }

   @Override
   protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
      if (key == null) {
         throw new InvalidKeySpecException("Key cannot be null");
      }
      throw new InvalidKeySpecException("Cannot extract Argon2KeySpec from derived key");
   }

   @Override
   protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
      if (key == null) {
         throw new InvalidKeyException("Key cannot be null");
      }

      if (key.getAlgorithm().equals(algorithm)) {
         return key;
      }

      byte[] encoded = key.getEncoded();
      if (encoded == null) {
         throw new InvalidKeyException("Key does not support encoding");
      }

      return new SecretKeySpec(encoded, algorithm);
   }
}
