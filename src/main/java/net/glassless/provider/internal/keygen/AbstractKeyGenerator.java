package net.glassless.provider.internal.keygen;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for key generators using OpenSSL's RAND_bytes.
 */
public abstract class AbstractKeyGenerator extends KeyGeneratorSpi {

   private final String algorithm;
   private final int defaultKeySize; // in bits
   private final int[] supportedKeySizes; // in bits, null means any size

   private int keySize; // in bits

   protected AbstractKeyGenerator(String algorithm, int defaultKeySize, int[] supportedKeySizes) {
      this.algorithm = algorithm;
      this.defaultKeySize = defaultKeySize;
      this.supportedKeySizes = supportedKeySizes;
      this.keySize = defaultKeySize;
   }

   @Override
   protected void engineInit(SecureRandom random) {
      this.keySize = defaultKeySize;
   }

   @Override
   protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported");
   }

   @Override
   protected void engineInit(int keysize, SecureRandom random) {
      if (supportedKeySizes != null) {
         boolean valid = false;
         for (int size : supportedKeySizes) {
            if (size == keysize) {
               valid = true;
               break;
            }
         }
         if (!valid) {
            throw new InvalidParameterException("Invalid key size: " + keysize + " bits");
         }
      }
      this.keySize = keysize;
   }

   @Override
   protected SecretKey engineGenerateKey() {
      byte[] keyBytes = null;
      try {
         int keySizeBytes = keySize / 8;
         keyBytes = OpenSSLCrypto.RAND_bytes(keySizeBytes);
         return new SecretKeySpec(keyBytes, algorithm);
      } catch (Throwable e) {
         throw new ProviderException("Error generating key", e);
      } finally {
         if (keyBytes != null) {
            Arrays.fill(keyBytes, (byte) 0);
         }
      }
   }
}
