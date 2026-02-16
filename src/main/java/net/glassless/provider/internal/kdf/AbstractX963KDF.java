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
 * Abstract base class for X9.63 KDF implementations.
 *
 * ANSI X9.63 KDF is used for key derivation in elliptic curve cryptography,
 * commonly after ECDH key agreement.
 */
public abstract class AbstractX963KDF extends KDFSpi {

   private final String algorithm;
   private final String digestName;
   private final KDFParameters params;

   protected AbstractX963KDF(KDFParameters params, String algorithm, String digestName)
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
      if (!(params instanceof X963KDFParameterSpec x963Params)) {
         throw new InvalidAlgorithmParameterException(
            "X963KDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      try {
         return deriveX963(x963Params);
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("X9.63 KDF derivation failed", e);
      }
   }

   private byte[] deriveX963(X963KDFParameterSpec params) throws Throwable {
      int kdf = OpenSSLCrypto.EVP_KDF_fetch(0, "X963KDF", 0);
      if (kdf == 0) {
         throw new ProviderException("Failed to fetch X963KDF");
      }

      try {
         int ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
         if (ctx == 0) {
            throw new ProviderException("Failed to create X963KDF context");
         }

         try {
            byte[] secret = params.getSharedSecret();
            byte[] info = params.getSharedInfo();
            int length = params.getKeyLength();

            int osslParams = OpenSSLCrypto.createX963KDFParams(digestName, secret, info);
            int output = OpenSSLCrypto.malloc(length);

            int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
            if (result != 1) {
               throw new ProviderException("X963KDF derivation failed");
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
