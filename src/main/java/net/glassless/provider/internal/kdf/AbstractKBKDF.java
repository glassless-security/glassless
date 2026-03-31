package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for KBKDF (SP 800-108) implementations.
 * <p>
 * KBKDF is a NIST-approved key derivation function that uses a
 * pseudorandom function (HMAC or CMAC) to derive keys.
 */
public abstract class AbstractKBKDF extends AbstractKDF {

   private final String macName;

   protected AbstractKBKDF(KDFParameters params, String algorithm, String macName, String digestName)
      throws InvalidAlgorithmParameterException {
      super(params, algorithm, digestName);
      this.macName = macName;
   }

   @Override
   protected byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable {
      if (!(params instanceof KBKDFParameterSpec kbParams)) {
         throw new InvalidAlgorithmParameterException(
            "KBKDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      MemorySegment osslParams = OpenSSLCrypto.createKBKDFParams(
         macName, digestName, kbParams.getKey(), kbParams.getLabel(),
         kbParams.getContext(), kbParams.getMode(), arena);

      return deriveWithKDF("KBKDF", osslParams, kbParams.getKeyLength(), arena);
   }
}
