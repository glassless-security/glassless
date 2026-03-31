package net.glassless.provider.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.ProviderException;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Shared KEM encapsulation/decapsulation logic using OpenSSL EVP_PKEY API.
 * Used by both ML-KEM and Hybrid KEM implementations.
 */
public final class KEMUtils {

   private KEMUtils() {
   }

   /**
    * Performs KEM encapsulation using an already-loaded EVP_PKEY.
    *
    * @param pkey             the loaded public key
    * @param from             start index in the shared secret
    * @param to               end index in the shared secret
    * @param algorithm        the algorithm name for the SecretKey
    * @param sharedSecretSize the total shared secret size (for range validation)
    * @param arena            the arena for memory allocation
    * @return the encapsulated result (secret key, ciphertext)
    */
   public static EncapsulateResult encapsulate(MemorySegment pkey, int from, int to,
                                               String algorithm, int sharedSecretSize, Arena arena) throws Throwable {
      if (from < 0 || from > to || to > sharedSecretSize) {
         throw new IllegalArgumentException("Invalid range: from=" + from + ", to=" + to);
      }

      MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
         MemorySegment.NULL, pkey, MemorySegment.NULL);
      if (ctx.equals(MemorySegment.NULL)) {
         throw new ProviderException("Failed to create EVP_PKEY_CTX");
      }

      try {
         int result = OpenSSLCrypto.EVP_PKEY_encapsulate_init(ctx, MemorySegment.NULL);
         if (result != 1) {
            throw new ProviderException("EVP_PKEY_encapsulate_init failed");
         }

         // Get required sizes
         MemorySegment wrappedLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
         MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);

         result = OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, MemorySegment.NULL, wrappedLenPtr,
            MemorySegment.NULL, secretLenPtr);
         if (result != 1) {
            throw new ProviderException("EVP_PKEY_encapsulate (get size) failed");
         }

         long wrappedLen = wrappedLenPtr.get(ValueLayout.JAVA_LONG, 0);
         long secretLen = secretLenPtr.get(ValueLayout.JAVA_LONG, 0);

         // Allocate buffers and perform encapsulation
         MemorySegment wrappedBuffer = arena.allocate(ValueLayout.JAVA_BYTE, wrappedLen);
         MemorySegment secretBuffer = arena.allocate(ValueLayout.JAVA_BYTE, secretLen);

         result = OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, wrappedBuffer, wrappedLenPtr,
            secretBuffer, secretLenPtr);
         if (result != 1) {
            throw new ProviderException("EVP_PKEY_encapsulate failed");
         }

         // Extract results
         byte[] ciphertext = new byte[OpenSSLCrypto.toIntSize(wrappedLenPtr.get(ValueLayout.JAVA_LONG, 0))];
         wrappedBuffer.asByteBuffer().get(ciphertext);

         byte[] fullSecret = new byte[OpenSSLCrypto.toIntSize(secretLenPtr.get(ValueLayout.JAVA_LONG, 0))];
         secretBuffer.asByteBuffer().get(fullSecret);

         // Create secret key from specified range
         byte[] keyBytes = new byte[to - from];
         System.arraycopy(fullSecret, from, keyBytes, 0, keyBytes.length);
         String keyAlgorithm = algorithm != null ? algorithm : "Generic";
         SecretKey secretKey = new SecretKeySpec(keyBytes, keyAlgorithm);

         return new EncapsulateResult(
            new KEM.Encapsulated(secretKey, ciphertext, null),
            ciphertext.length);
      } finally {
         OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
      }
   }

   /**
    * Queries the encapsulation size for a loaded public key without performing
    * a full encapsulation.
    *
    * @return the encapsulation size, or -1 if it could not be determined
    */
   public static int queryEncapsulationSize(MemorySegment pkey, Arena arena) throws Throwable {
      MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
         MemorySegment.NULL, pkey, MemorySegment.NULL);
      if (ctx.equals(MemorySegment.NULL)) {
         return -1;
      }

      try {
         if (OpenSSLCrypto.EVP_PKEY_encapsulate_init(ctx, MemorySegment.NULL) != 1) {
            return -1;
         }
         MemorySegment wrappedLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
         MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
         if (OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, MemorySegment.NULL, wrappedLenPtr,
            MemorySegment.NULL, secretLenPtr) != 1) {
            return -1;
         }
         return OpenSSLCrypto.toIntSize(wrappedLenPtr.get(ValueLayout.JAVA_LONG, 0));
      } finally {
         OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
      }
   }

   /**
    * Performs KEM decapsulation using an already-loaded EVP_PKEY.
    *
    * @param pkey             the loaded private key
    * @param encapsulation    the ciphertext to decapsulate
    * @param from             start index in the shared secret
    * @param to               end index in the shared secret
    * @param algorithm        the algorithm name for the SecretKey
    * @param sharedSecretSize the total shared secret size (for range validation)
    * @param arena            the arena for memory allocation
    * @return the derived SecretKey
    */
   public static SecretKey decapsulate(MemorySegment pkey, byte[] encapsulation, int from, int to,
                                       String algorithm, int sharedSecretSize, Arena arena)
      throws Throwable, DecapsulateException {
      if (from < 0 || from > to || to > sharedSecretSize) {
         throw new IllegalArgumentException("Invalid range: from=" + from + ", to=" + to);
      }

      MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
         MemorySegment.NULL, pkey, MemorySegment.NULL);
      if (ctx.equals(MemorySegment.NULL)) {
         throw new DecapsulateException("Failed to create EVP_PKEY_CTX");
      }

      try {
         int result = OpenSSLCrypto.EVP_PKEY_decapsulate_init(ctx, MemorySegment.NULL);
         if (result != 1) {
            throw new DecapsulateException("EVP_PKEY_decapsulate_init failed");
         }

         // Prepare encapsulation buffer
         MemorySegment wrappedBuffer = arena.allocate(ValueLayout.JAVA_BYTE, encapsulation.length);
         wrappedBuffer.asByteBuffer().put(encapsulation);

         // Get required size
         MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
         result = OpenSSLCrypto.EVP_PKEY_decapsulate(ctx, MemorySegment.NULL, secretLenPtr,
            wrappedBuffer, encapsulation.length);
         if (result != 1) {
            throw new DecapsulateException("EVP_PKEY_decapsulate (get size) failed");
         }

         long secretLen = secretLenPtr.get(ValueLayout.JAVA_LONG, 0);
         MemorySegment secretBuffer = arena.allocate(ValueLayout.JAVA_BYTE, secretLen);

         // Perform decapsulation
         result = OpenSSLCrypto.EVP_PKEY_decapsulate(ctx, secretBuffer, secretLenPtr,
            wrappedBuffer, encapsulation.length);
         if (result != 1) {
            throw new DecapsulateException("EVP_PKEY_decapsulate failed");
         }

         // Extract result
         byte[] fullSecret = new byte[OpenSSLCrypto.toIntSize(secretLenPtr.get(ValueLayout.JAVA_LONG, 0))];
         secretBuffer.asByteBuffer().get(fullSecret);

         // Create secret key from specified range
         byte[] keyBytes = new byte[to - from];
         System.arraycopy(fullSecret, from, keyBytes, 0, keyBytes.length);
         String keyAlgorithm = algorithm != null ? algorithm : "Generic";
         return new SecretKeySpec(keyBytes, keyAlgorithm);
      } finally {
         OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
      }
   }

   /**
    * Result of an encapsulation operation.
    */
   public record EncapsulateResult(KEM.Encapsulated encapsulated, int encapsulationSize) {
   }
}
