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
 * Abstract base class for TLS PRF implementations.
 *
 * TLS PRF is used for key derivation in TLS 1.0-1.2.
 * TLS 1.2 uses a single hash function (typically SHA-256).
 */
public abstract class AbstractTLSPRF extends KDFSpi {

   private final String algorithm;
   private final String digestName;
   private final KDFParameters params;

   protected AbstractTLSPRF(KDFParameters params, String algorithm, String digestName)
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
      if (!(params instanceof TLSPRFParameterSpec tlsParams)) {
         throw new InvalidAlgorithmParameterException(
            "TLSPRFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      try (Arena arena = Arena.ofConfined()) {
         return deriveTLSPRF(tlsParams, arena);
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("TLS-PRF derivation failed", e);
      }
   }

   private byte[] deriveTLSPRF(TLSPRFParameterSpec params, Arena arena) throws Throwable {
      MemorySegment kdf = OpenSSLCrypto.EVP_KDF_fetch(MemorySegment.NULL, "TLS1-PRF", MemorySegment.NULL, arena);
      if (kdf == null || kdf.address() == 0) {
         throw new ProviderException("Failed to fetch TLS1-PRF");
      }

      try {
         MemorySegment ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
         if (ctx == null || ctx.address() == 0) {
            throw new ProviderException("Failed to create TLS1-PRF context");
         }

         try {
            byte[] secret = params.getSecret();
            byte[] labelAndSeed = params.getLabelAndSeed();
            int length = params.getKeyLength();

            MemorySegment osslParams = OpenSSLCrypto.createTLSPRFParams(
               digestName, secret, labelAndSeed, arena);
            MemorySegment output = arena.allocate(ValueLayout.JAVA_BYTE, length);

            int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
            if (result != 1) {
               throw new ProviderException("TLS-PRF derivation failed");
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
