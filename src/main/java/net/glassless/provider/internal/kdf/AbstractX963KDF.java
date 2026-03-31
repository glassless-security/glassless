package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for X9.63 KDF implementations.
 * <p>
 * ANSI X9.63 KDF is used for key derivation in elliptic curve cryptography,
 * commonly after ECDH key agreement.
 */
public abstract class AbstractX963KDF extends AbstractKDF {

   protected AbstractX963KDF(KDFParameters params, String algorithm, String digestName)
      throws InvalidAlgorithmParameterException {
      super(params, algorithm, digestName);
   }

   @Override
   protected byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable {
      if (!(params instanceof X963KDFParameterSpec x963Params)) {
         throw new InvalidAlgorithmParameterException(
            "X963KDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      MemorySegment osslParams = OpenSSLCrypto.createX963KDFParams(
         digestName, x963Params.getSharedSecret(), x963Params.getSharedInfo(), arena);

      return deriveWithKDF("X963KDF", osslParams, x963Params.getKeyLength(), arena);
   }
}
