package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for TLS PRF implementations.
 * <p>
 * TLS PRF is used for key derivation in TLS 1.0-1.2.
 * TLS 1.2 uses a single hash function (typically SHA-256).
 */
public abstract class AbstractTLSPRF extends AbstractKDF {

   protected AbstractTLSPRF(KDFParameters params, String algorithm, String digestName)
      throws InvalidAlgorithmParameterException {
      super(params, algorithm, digestName);
   }

   @Override
   protected byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable {
      if (!(params instanceof TLSPRFParameterSpec tlsParams)) {
         throw new InvalidAlgorithmParameterException(
            "TLSPRFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      MemorySegment osslParams = OpenSSLCrypto.createTLSPRFParams(
         digestName, tlsParams.getSecret(), tlsParams.getLabelAndSeed(), arena);

      return deriveWithKDF("TLS1-PRF", osslParams, tlsParams.getKeyLength(), arena);
   }
}
