package net.glassless.provider.internal.lms;

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

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * LMS (Leighton-Micali Signature) verification implementation using OpenSSL.
 * LMS is a stateful hash-based signature scheme (RFC 8554 / NIST SP 800-208).
 *
 * <p>This implementation is <b>verification-only</b>. Signing and key generation
 * are not supported because LMS is a stateful scheme where each private key
 * can only sign a limited number of messages, and state management must be
 * handled by the key owner.
 *
 * <p>LMS uses single-shot verification (EVP_DigestVerify) similar to SLH-DSA.
 */
public class LMSSignature extends SignatureSpi {

   private byte[] publicKeyEncoded;
   private final ByteArrayOutputStream dataBuffer;

   public LMSSignature() {
      this.dataBuffer = new ByteArrayOutputStream();
   }

   @Override
   protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      throw new InvalidKeyException("LMS signing is not supported. " +
         "LMS is a stateful signature scheme; only verification is available.");
   }

   @Override
   protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      if (publicKey == null) {
         throw new InvalidKeyException("Public key cannot be null");
      }

      String keyAlgorithm = publicKey.getAlgorithm();
      if (!"LMS".equalsIgnoreCase(keyAlgorithm) && !"HSS".equalsIgnoreCase(keyAlgorithm)) {
         throw new InvalidKeyException("LMS public key required, got: " + keyAlgorithm);
      }

      this.publicKeyEncoded = publicKey.getEncoded();
      if (this.publicKeyEncoded == null) {
         throw new InvalidKeyException("Public key encoding is null");
      }

      this.dataBuffer.reset();
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
      throw new SignatureException("LMS signing is not supported. " +
         "LMS is a stateful signature scheme; only verification is available.");
   }

   @Override
   protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      byte[] data = dataBuffer.toByteArray();
      dataBuffer.reset();

      try (Arena arena = Arena.ofConfined()) {
         // Load the public key
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new SignatureException("Failed to load LMS public key");
         }

         try {
            // Create message digest context for verification
            MemorySegment mdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
            if (mdCtx.equals(MemorySegment.NULL)) {
               throw new SignatureException("Failed to create EVP_MD_CTX");
            }

            try {
               // Initialize verification - LMS uses NULL for digest (built into algorithm)
               int result = OpenSSLCrypto.EVP_DigestVerifyInit(mdCtx, MemorySegment.NULL,
                  MemorySegment.NULL, MemorySegment.NULL, pkey);
               if (result != 1) {
                  throw new SignatureException("EVP_DigestVerifyInit failed for LMS");
               }

               // Prepare signature segment
               MemorySegment sigSegment = arena.allocate(ValueLayout.JAVA_BYTE, sigBytes.length);
               sigSegment.asByteBuffer().put(sigBytes);

               // Prepare data segment
               MemorySegment dataSegment;
               if (data.length > 0) {
                  dataSegment = arena.allocate(ValueLayout.JAVA_BYTE, data.length);
                  dataSegment.asByteBuffer().put(data);
               } else {
                  dataSegment = MemorySegment.NULL;
               }

               // Single-shot verification
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
         throw new SignatureException("LMS verification failed", e);
      }
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
