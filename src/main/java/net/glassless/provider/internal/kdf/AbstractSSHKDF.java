package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for SSH KDF implementations (RFC 4253).
 * <p>
 * SSH KDF derives encryption keys, integrity keys, and IVs from
 * the shared secret established during SSH key exchange.
 */
public abstract class AbstractSSHKDF extends AbstractKDF {

   protected AbstractSSHKDF(KDFParameters params, String algorithm, String digestName)
      throws InvalidAlgorithmParameterException {
      super(params, algorithm, digestName);
   }

   @Override
   protected byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable {
      if (!(params instanceof SSHKDFParameterSpec sshParams)) {
         throw new InvalidAlgorithmParameterException(
            "SSHKDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      MemorySegment osslParams = OpenSSLCrypto.createSSHKDFParams(
         digestName, sshParams.getKey(), sshParams.getXcghash(),
         sshParams.getSessionId(), sshParams.getType(), arena);

      return deriveWithKDF("SSHKDF", osslParams, sshParams.getKeyLength(), arena);
   }
}
