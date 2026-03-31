package net.glassless.provider.internal.secretkeyfactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for Argon2 SecretKeyFactory implementations.
 * <p>
 * Argon2 is a password hashing algorithm that was the winner of the
 * Password Hashing Competition (PHC). It comes in three variants:
 * - Argon2d: Data-dependent, faster, more resistant to GPU attacks
 * - Argon2i: Data-independent, more resistant to side-channel attacks
 * - Argon2id: Hybrid of Argon2d and Argon2i (recommended)
 * <p>
 * Requires OpenSSL 3.2 or later.
 */
public abstract class AbstractArgon2SecretKeyFactory extends AbstractSecretKeyFactory {

   private final String kdfName;

   protected AbstractArgon2SecretKeyFactory(String algorithm, String kdfName) {
      super(algorithm);
      this.kdfName = kdfName;
   }

   @Override
   protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
      if (!(keySpec instanceof Argon2KeySpec argon2Spec)) {
         throw new InvalidKeySpecException("KeySpec must be an Argon2KeySpec");
      }

      char[] password = argon2Spec.getPassword();
      byte[] salt = argon2Spec.getSalt();
      int iterations = argon2Spec.getIterations();
      int memoryKB = argon2Spec.getMemoryKB();
      int parallelism = argon2Spec.getParallelism();
      int keyLengthBytes = argon2Spec.getKeyLength() / 8;
      byte[] ad = argon2Spec.getAssociatedData();
      byte[] secret = argon2Spec.getSecret();

      try (Arena arena = Arena.ofConfined()) {
         byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);

         try {
            MemorySegment kdf = OpenSSLCrypto.EVP_KDF_fetch(MemorySegment.NULL, kdfName, MemorySegment.NULL, arena);
            if (kdf.equals(MemorySegment.NULL)) {
               throw new ProviderException("Failed to fetch " + kdfName + " KDF. Requires OpenSSL 3.2+");
            }

            try {
               MemorySegment ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
               if (ctx.equals(MemorySegment.NULL)) {
                  throw new ProviderException("Failed to create " + kdfName + " context");
               }

               try {
                  MemorySegment osslParams = OpenSSLCrypto.createArgon2Params(
                     passwordBytes, salt, iterations, memoryKB, parallelism, ad, secret, arena);

                  MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, keyLengthBytes);

                  int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, keyLengthBytes, osslParams);
                  if (result != 1) {
                     throw new ProviderException(kdfName + " key derivation failed");
                  }

                  byte[] derivedKey = new byte[keyLengthBytes];
                  output.asByteBuffer().get(derivedKey);

                  return createKey(derivedKey);
               } finally {
                  OpenSSLCrypto.EVP_KDF_CTX_free(ctx);
               }
            } finally {
               OpenSSLCrypto.EVP_KDF_free(kdf);
            }
         } finally {
            Arrays.fill(passwordBytes, (byte) 0);
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error deriving key with " + kdfName, e);
      }
   }
}
