package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for SSH KDF implementations (RFC 4253).
 *
 * SSH KDF derives encryption keys, integrity keys, and IVs from
 * the shared secret established during SSH key exchange.
 */
public abstract class AbstractSSHKDF extends KDFSpi {

   private final String algorithm;
   private final String digestName;
   private final KDFParameters params;

   protected AbstractSSHKDF(KDFParameters params, String algorithm, String digestName)
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
         throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
      byte[] derivedBytes = engineDeriveData(params);
      return new SecretKeySpec(derivedBytes, algorithm);
   }

   @Override
   protected byte[] engineDeriveData(AlgorithmParameterSpec params)
         throws InvalidAlgorithmParameterException {
      if (!(params instanceof SSHKDFParameterSpec sshParams)) {
         throw new InvalidAlgorithmParameterException(
            "SSHKDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      try (Arena arena = Arena.ofConfined()) {
         return deriveSSHKDF(sshParams, arena);
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("SSHKDF derivation failed", e);
      }
   }

   private byte[] deriveSSHKDF(SSHKDFParameterSpec params, Arena arena) throws Throwable {
      MemorySegment kdf = OpenSSLCrypto.EVP_KDF_fetch(MemorySegment.NULL, "SSHKDF", MemorySegment.NULL, arena);
      if (kdf.equals(MemorySegment.NULL)) {
         throw new ProviderException("Failed to fetch SSHKDF");
      }

      try {
         MemorySegment ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
         if (ctx.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to create SSHKDF context");
         }

         try {
            byte[] key = params.getKey();
            byte[] xcghash = params.getXcghash();
            byte[] sessionId = params.getSessionId();
            char type = params.getType();
            int length = params.getKeyLength();

            MemorySegment osslParams = OpenSSLCrypto.createSSHKDFParams(
               digestName, key, xcghash, sessionId, type, arena);
            MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, length);

            int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
            if (result != 1) {
               throw new ProviderException("SSHKDF derivation failed");
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
