package net.glassless.provider.internal.signature;

import java.lang.foreign.MemorySegment;
import java.security.ProviderException;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Base class for deterministic ECDSA signatures (RFC 6979 / FIPS 186-5).
 * Sets the nonce-type parameter to deterministic on the signing context.
 */
abstract class AbstractDeterministicECDSASignature extends AbstractSignature {

   protected AbstractDeterministicECDSASignature(String digestAlgorithm) {
      super(digestAlgorithm);
   }

   @Override
   protected void configureContext(MemorySegment pkeyCtx) throws Throwable {
      MemorySegment params = OpenSSLCrypto.createNonceTypeParams(1, arena);
      int result = OpenSSLCrypto.EVP_PKEY_CTX_set_params(pkeyCtx, params);
      if (result != 1) {
         throw new ProviderException("Failed to set deterministic nonce type (RFC 6979)");
      }
   }
}
