package net.glassless.provider.internal.algparamgen;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.ProviderException;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for AlgorithmParameterGenerator implementations
 * using the OpenSSL EVP_PKEY paramgen API.
 */
abstract class AbstractParameterGenerator extends AlgorithmParameterGeneratorSpi {

   private final String opensslAlgorithm;

   protected AbstractParameterGenerator(String opensslAlgorithm) {
      this.opensslAlgorithm = opensslAlgorithm;
   }

   @Override
   protected AlgorithmParameters engineGenerateParameters() {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
            MemorySegment.NULL, opensslAlgorithm, MemorySegment.NULL, arena);
         if (ctx.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to create EVP_PKEY_CTX for " + opensslAlgorithm);
         }

         try {
            int result = OpenSSLCrypto.EVP_PKEY_paramgen_init(ctx);
            if (result != 1) {
               throw new ProviderException("EVP_PKEY_paramgen_init failed");
            }

            configureParameters(ctx);

            MemorySegment pkeyPtr = arena.allocate(ValueLayout.ADDRESS);
            result = OpenSSLCrypto.EVP_PKEY_paramgen(ctx, pkeyPtr);
            if (result != 1) {
               throw new ProviderException("EVP_PKEY_paramgen failed");
            }

            MemorySegment pkey = pkeyPtr.get(ValueLayout.ADDRESS, 0);
            if (pkey.equals(MemorySegment.NULL)) {
               throw new ProviderException("Generated parameter key is null");
            }

            try {
               return extractParameters(pkey, arena);
            } finally {
               OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
         } finally {
            OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating " + opensslAlgorithm + " parameters", e);
      }
   }

   /**
    * Sets algorithm-specific parameters on the EVP_PKEY_CTX before paramgen.
    */
   protected abstract void configureParameters(MemorySegment ctx) throws Throwable;

   /**
    * Extracts the generated parameters from the EVP_PKEY and returns
    * an initialized AlgorithmParameters object.
    */
   protected abstract AlgorithmParameters extractParameters(MemorySegment pkey, Arena arena) throws Throwable;
}
