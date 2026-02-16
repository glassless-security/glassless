package net.glassless.provider.internal.kdf;

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
 * Abstract base class for TLS 1.3 KDF implementations.
 *
 * TLS 1.3 uses HKDF for key derivation with two modes:
 * <ul>
 *   <li>EXTRACT_ONLY: HKDF-Extract to derive PRK from input key material</li>
 *   <li>EXPAND_ONLY: HKDF-Expand-Label to derive keys from PRK</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8446#section-7.1">RFC 8446 Section 7.1</a>
 */
public abstract class AbstractTLS13KDF extends KDFSpi {

   private final String algorithm;
   private final String digestName;
   private final KDFParameters params;

   protected AbstractTLS13KDF(KDFParameters params, String algorithm, String digestName)
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
      if (!(params instanceof TLS13KDFParameterSpec tlsParams)) {
         throw new InvalidAlgorithmParameterException(
            "TLS13KDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      try {
         return deriveTLS13KDF(tlsParams);
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("TLS 1.3 KDF derivation failed", e);
      }
   }

   private byte[] deriveTLS13KDF(TLS13KDFParameterSpec params) throws Throwable {
      int kdf = OpenSSLCrypto.EVP_KDF_fetch(0, "TLS13-KDF", 0);
      if (kdf == 0) {
         throw new ProviderException("Failed to fetch TLS13-KDF");
      }

      try {
         int ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
         if (ctx == 0) {
            throw new ProviderException("Failed to create TLS13-KDF context");
         }

         try {
            int length = params.getKeyLength();
            int osslParams = OpenSSLCrypto.createTLS13KDFParams(
               digestName,
               params.getModeString(),
               params.getKey(),
               params.getSalt(),
               params.getPrefix(),
               params.getLabel(),
               params.getData());

            int output = OpenSSLCrypto.malloc(length);

            int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
            if (result != 1) {
               throw new ProviderException("TLS 1.3 KDF derivation failed");
            }

            byte[] derived = OpenSSLCrypto.memory().readBytes(output, length);
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
