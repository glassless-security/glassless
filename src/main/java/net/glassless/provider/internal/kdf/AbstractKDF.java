package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidAlgorithmParameterException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for all KDF implementations using OpenSSL's EVP_KDF API.
 * Provides common boilerplate for parameter handling, key derivation, and
 * OpenSSL KDF context lifecycle management.
 */
public abstract class AbstractKDF extends KDFSpi {

   private final String algorithm;
   protected final String digestName;
   private final KDFParameters params;

   protected AbstractKDF(KDFParameters params, String algorithm, String digestName)
      throws InvalidAlgorithmParameterException {
      super(params);
      this.params = params;
      this.algorithm = algorithm;
      this.digestName = digestName;
   }

   @Override
   protected KDFParameters engineGetParameters() {
      return params;
   }

   @Override
   protected SecretKey engineDeriveKey(String algorithm, AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
      byte[] derivedBytes = engineDeriveData(params);
      return new SecretKeySpec(derivedBytes, algorithm);
   }

   @Override
   protected byte[] engineDeriveData(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
      try (Arena arena = Arena.ofConfined()) {
         return derive(params, arena);
      } catch (InvalidAlgorithmParameterException | ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException(getAlgorithm() + " derivation failed", e);
      }
   }

   /**
    * Performs the actual key derivation. Subclasses must validate the parameter type,
    * build OpenSSL params, and call {@link #deriveWithKDF} or perform custom derivation.
    */
   protected abstract byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable;

   /**
    * Common helper that fetches an OpenSSL KDF by name, creates a context,
    * calls {@code EVP_KDF_derive}, and returns the derived bytes.
    *
    * @param opensslKdfName the OpenSSL KDF name (e.g., "HKDF", "SSHKDF", "KBKDF")
    * @param osslParams     the OSSL_PARAM array for the KDF
    * @param length         the number of bytes to derive
    * @param arena          the arena for memory allocation
    * @return the derived key bytes
    */
   protected byte[] deriveWithKDF(String opensslKdfName, MemorySegment osslParams, int length, Arena arena)
      throws Throwable {
      MemorySegment kdf = OpenSSLCrypto.EVP_KDF_fetch(MemorySegment.NULL, opensslKdfName, MemorySegment.NULL, arena);
      if (kdf.equals(MemorySegment.NULL)) {
         throw new ProviderException("Failed to fetch " + opensslKdfName);
      }

      try {
         MemorySegment ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
         if (ctx.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to create " + opensslKdfName + " context");
         }

         try {
            MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, length);

            int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
            if (result != 1) {
               throw new ProviderException(opensslKdfName + " derivation failed");
            }

            byte[] derived = new byte[length];
            output.asByteBuffer().get(derived);
            return derived;
         } finally {
            OpenSSLCrypto.EVP_KDF_CTX_free(ctx);
         }
      } finally {
         OpenSSLCrypto.EVP_KDF_free(kdf);
      }
   }

   public String getAlgorithm() {
      return algorithm;
   }
}
