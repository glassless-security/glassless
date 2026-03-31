package net.glassless.provider.internal.kdf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

import javax.crypto.KDFParameters;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for HKDF (HMAC-based Extract-and-Expand Key Derivation Function) implementations.
 * Implements RFC 5869 using OpenSSL's EVP_KDF API.
 */
public abstract class AbstractHKDF extends AbstractKDF {

   private final int hashLength;

   protected AbstractHKDF(KDFParameters params, String algorithm, String digestName, int hashLength)
      throws InvalidAlgorithmParameterException {
      super(params, algorithm, digestName);
      this.hashLength = hashLength;
   }

   @Override
   protected byte[] derive(AlgorithmParameterSpec params, Arena arena)
      throws InvalidAlgorithmParameterException, Throwable {
      if (!(params instanceof HKDFParameterSpec hkdfParams)) {
         throw new InvalidAlgorithmParameterException(
            "HKDFParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }

      return switch (hkdfParams) {
         case HKDFParameterSpec.Extract extract -> deriveExtract(extract, arena);
         case HKDFParameterSpec.Expand expand -> deriveExpand(expand, arena);
         case HKDFParameterSpec.ExtractThenExpand extractExpand -> deriveExtractExpand(extractExpand, arena);
         default -> throw new InvalidAlgorithmParameterException(
            "Unsupported HKDFParameterSpec type: " + hkdfParams.getClass().getName());
      };
   }

   private byte[] deriveExtract(HKDFParameterSpec.Extract params, Arena arena) throws Throwable {
      byte[] ikm = concatenateKeys(params.ikms());
      byte[] salt = concatenateKeys(params.salts());
      if (salt.length == 0) {
         salt = new byte[hashLength];
      }

      MemorySegment osslParams = OpenSSLCrypto.createHKDFParams(
         digestName, OpenSSLCrypto.HKDF_MODE_EXTRACT_ONLY, salt, ikm, null, arena);

      return deriveWithKDF("HKDF", osslParams, hashLength, arena);
   }

   private byte[] deriveExpand(HKDFParameterSpec.Expand params, Arena arena) throws Throwable {
      byte[] prk = params.prk().getEncoded();
      byte[] info = params.info();
      if (info == null) info = new byte[0];

      MemorySegment osslParams = OpenSSLCrypto.createHKDFParams(
         digestName, OpenSSLCrypto.HKDF_MODE_EXPAND_ONLY, null, prk, info, arena);

      return deriveWithKDF("HKDF", osslParams, params.length(), arena);
   }

   private byte[] deriveExtractExpand(HKDFParameterSpec.ExtractThenExpand params, Arena arena) throws Throwable {
      byte[] ikm = concatenateKeys(params.ikms());
      byte[] salt = concatenateKeys(params.salts());
      if (salt.length == 0) {
         salt = new byte[hashLength];
      }
      byte[] info = params.info();
      if (info == null) info = new byte[0];

      MemorySegment osslParams = OpenSSLCrypto.createHKDFParams(
         digestName, OpenSSLCrypto.HKDF_MODE_EXTRACT_AND_EXPAND, salt, ikm, info, arena);

      return deriveWithKDF("HKDF", osslParams, params.length(), arena);
   }

   private byte[] concatenateKeys(List<SecretKey> keys) {
      if (keys == null || keys.isEmpty()) {
         return new byte[0];
      }
      if (keys.size() == 1) {
         return keys.getFirst().getEncoded();
      }

      int totalLength = 0;
      for (SecretKey key : keys) {
         totalLength += key.getEncoded().length;
      }

      byte[] result = new byte[totalLength];
      int offset = 0;
      for (SecretKey key : keys) {
         byte[] encoded = key.getEncoded();
         System.arraycopy(encoded, 0, result, offset, encoded.length);
         offset += encoded.length;
      }

      return result;
   }
}
