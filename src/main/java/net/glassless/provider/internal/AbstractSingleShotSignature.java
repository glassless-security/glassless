package net.glassless.provider.internal;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Abstract base for signature algorithms that use single-shot
 * EVP_DigestSign/EVP_DigestVerify (e.g., EdDSA, ML-DSA, SLH-DSA, LMS).
 *
 * <p>These algorithms have built-in hashing, so they pass NULL for the digest
 * handle and buffer all data until sign/verify.
 *
 * <p>Subclasses must implement {@link #validateAndInitSign} and
 * {@link #validateAndInitVerify} for algorithm-specific key validation.
 */
public abstract class AbstractSingleShotSignature extends SignatureSpi {

   private final String algorithmName;
   protected byte[] privateKeyEncoded;
   protected byte[] publicKeyEncoded;
   protected final ByteArrayOutputStream dataBuffer;
   protected boolean signing;

   protected AbstractSingleShotSignature(String algorithmName) {
      this.algorithmName = algorithmName;
      this.dataBuffer = new ByteArrayOutputStream();
   }

   /**
    * Validates the private key and extracts its encoded form.
    * Implementations should check key type and algorithm variant.
    *
    * @throws InvalidKeyException if the key is not valid for this algorithm
    */
   protected abstract void validateAndInitSign(PrivateKey privateKey) throws InvalidKeyException;

   /**
    * Validates the public key and extracts its encoded form.
    * Implementations should check key type and algorithm variant.
    *
    * @throws InvalidKeyException if the key is not valid for this algorithm
    */
   protected abstract void validateAndInitVerify(PublicKey publicKey) throws InvalidKeyException;

   @Override
   protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      validateAndInitSign(privateKey);
      this.publicKeyEncoded = null;
      this.dataBuffer.reset();
      this.signing = true;
   }

   @Override
   protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      validateAndInitVerify(publicKey);
      this.privateKeyEncoded = null;
      this.dataBuffer.reset();
      this.signing = false;
   }

   @Override
   protected void engineUpdate(byte b) throws SignatureException {
      dataBuffer.write(b);
   }

   @Override
   protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
      dataBuffer.write(b, off, len);
   }

   @Override
   protected byte[] engineSign() throws SignatureException {
      if (!signing) {
         throw new SignatureException("Not initialized for signing");
      }

      byte[] data = dataBuffer.toByteArray();
      dataBuffer.reset();

      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new SignatureException("Failed to load private key");
         }

         try {
            MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
            if (mdCtx.equals(MemorySegment.NULL)) {
               throw new SignatureException("Failed to create EVP_MD_CTX");
            }

            try {
               int result = OpenSSLCrypto.EVP_DigestSignInit(mdCtx, MemorySegment.NULL,
                  MemorySegment.NULL, MemorySegment.NULL, pkey);
               if (result != 1) {
                  throw new SignatureException("EVP_DigestSignInit failed");
               }

               MemorySegment sigLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
               MemorySegment dataSegment = allocateData(data, arena);

               result = OpenSSLCrypto.EVP_DigestSign(mdCtx, MemorySegment.NULL, sigLenPtr,
                  dataSegment, data.length);
               if (result != 1) {
                  throw new SignatureException("EVP_DigestSign (get length) failed");
               }

               long sigLen = sigLenPtr.get(ValueLayout.JAVA_LONG, 0);
               MemorySegment sigBuffer = arena.allocate(ValueLayout.JAVA_BYTE, sigLen);

               result = OpenSSLCrypto.EVP_DigestSign(mdCtx, sigBuffer, sigLenPtr,
                  dataSegment, data.length);
               if (result != 1) {
                  throw new SignatureException("EVP_DigestSign failed");
               }

               long actualLen = sigLenPtr.get(ValueLayout.JAVA_LONG, 0);
               byte[] signature = new byte[(int) actualLen];
               sigBuffer.asByteBuffer().get(signature);

               return signature;
            } finally {
               OpenSSLCrypto.EVP_MD_CTX_free(mdCtx);
            }
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (SignatureException e) {
         throw e;
      } catch (Throwable e) {
         throw new SignatureException(algorithmName + " signing failed", e);
      }
   }

   @Override
   protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      if (signing) {
         throw new SignatureException("Not initialized for verification");
      }

      byte[] data = dataBuffer.toByteArray();
      dataBuffer.reset();

      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new SignatureException("Failed to load public key");
         }

         try {
            MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
            if (mdCtx.equals(MemorySegment.NULL)) {
               throw new SignatureException("Failed to create EVP_MD_CTX");
            }

            try {
               int result = OpenSSLCrypto.EVP_DigestVerifyInit(mdCtx, MemorySegment.NULL,
                  MemorySegment.NULL, MemorySegment.NULL, pkey);
               if (result != 1) {
                  throw new SignatureException("EVP_DigestVerifyInit failed");
               }

               MemorySegment sigSegment = arena.allocate(ValueLayout.JAVA_BYTE, sigBytes.length);
               sigSegment.asByteBuffer().put(sigBytes);

               MemorySegment dataSegment = allocateData(data, arena);

               result = OpenSSLCrypto.EVP_DigestVerify(mdCtx, sigSegment, sigBytes.length,
                  dataSegment, data.length);

               return result == 1;
            } finally {
               OpenSSLCrypto.EVP_MD_CTX_free(mdCtx);
            }
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (SignatureException e) {
         throw e;
      } catch (Throwable e) {
         throw new SignatureException(algorithmName + " verification failed", e);
      }
   }

   private static MemorySegment allocateData(byte[] data, Arena arena) {
      if (data.length > 0) {
         MemorySegment segment = arena.allocate(ValueLayout.JAVA_BYTE, data.length);
         segment.asByteBuffer().put(data);
         return segment;
      }
      return MemorySegment.NULL;
   }

   @Override
   @Deprecated
   protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
      throw new InvalidParameterException("No parameters supported");
   }

   @Override
   @Deprecated
   protected Object engineGetParameter(String param) throws InvalidParameterException {
      throw new InvalidParameterException("No parameters supported");
   }
}
