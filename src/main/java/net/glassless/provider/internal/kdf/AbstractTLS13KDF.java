package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for TLS 1.3 KDF implementations.
 * <p>
 * TLS 1.3 uses HKDF for key derivation with two modes:
 * <ul>
 *   <li>EXTRACT_ONLY: HKDF-Extract to derive PRK from input key material</li>
 *   <li>EXPAND_ONLY: HKDF-Expand-Label to derive keys from PRK</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8446#section-7.1">RFC 8446 Section 7.1</a>
 */
public abstract class AbstractTLS13KDF extends AbstractKDF {

   protected AbstractTLS13KDF(KDFParameters params, String algorithm, String digestName)
      throws InvalidAlgorithmParameterException {
      super(params, algorithm, digestName);
   }

   @Override
   protected byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable {
      if (!(params instanceof TLS13KDFParameterSpec tlsParams)) {
         throw new InvalidAlgorithmParameterException(
            "TLS13KDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      MemorySegment osslParams = OpenSSLCrypto.createTLS13KDFParams(
         digestName, tlsParams.getModeString(), tlsParams.getKey(),
         tlsParams.getSalt(), tlsParams.getPrefix(), tlsParams.getLabel(),
         tlsParams.getData(), arena);

      return deriveWithKDF("TLS13-KDF", osslParams, tlsParams.getKeyLength(), arena);
   }
}
