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
 * Abstract base class for KBKDF (SP 800-108) implementations.
 *
 * KBKDF is a NIST-approved key derivation function that uses a
 * pseudorandom function (HMAC or CMAC) to derive keys.
 */
public abstract class AbstractKBKDF extends KDFSpi {

   private final String algorithm;
   private final String macName;
   private final String digestName;
   private final KDFParameters params;

   protected AbstractKBKDF(KDFParameters params, String algorithm, String macName, String digestName)
         throws InvalidAlgorithmParameterException {
      super(params);
      this.params = params;
      this.algorithm = algorithm;
      this.macName = macName;
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
      if (!(params instanceof KBKDFParameterSpec kbParams)) {
         throw new InvalidAlgorithmParameterException(
            "KBKDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      try {
         return deriveKBKDF(kbParams);
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("KBKDF derivation failed", e);
      }
   }

   private byte[] deriveKBKDF(KBKDFParameterSpec params) throws Throwable {
      int kdf = OpenSSLCrypto.EVP_KDF_fetch(0, "KBKDF", 0);
      if (kdf == 0) {
         throw new ProviderException("Failed to fetch KBKDF");
      }

      try {
         int ctx = OpenSSLCrypto.EVP_KDF_CTX_new(kdf);
         if (ctx == 0) {
            throw new ProviderException("Failed to create KBKDF context");
         }

         try {
            byte[] key = params.getKey();
            byte[] label = params.getLabel();
            byte[] context = params.getContext();
            String mode = params.getMode();
            int length = params.getKeyLength();

            int osslParams = OpenSSLCrypto.createKBKDFParams(
               macName, digestName, key, label, context, mode);
            int output = OpenSSLCrypto.malloc(length);

            int result = OpenSSLCrypto.EVP_KDF_derive(ctx, output, length, osslParams);
            if (result != 1) {
               throw new ProviderException("KBKDF derivation failed");
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
