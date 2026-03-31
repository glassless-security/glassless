package net.glassless.provider.internal.secretkeyfactory;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

/**
 * Abstract base class for all SecretKeyFactory implementations.
 * Provides common {@code engineGetKeySpec} and {@code engineTranslateKey} implementations.
 */
public abstract class AbstractSecretKeyFactory extends SecretKeyFactorySpi {

   protected final String algorithm;

   protected AbstractSecretKeyFactory(String algorithm) {
      this.algorithm = algorithm;
   }

   @Override
   protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass) throws InvalidKeySpecException {
      if (key == null) {
         throw new InvalidKeySpecException("Key cannot be null");
      }
      throw new InvalidKeySpecException("Cannot extract key spec from derived key");
   }

   @Override
   protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
      if (key == null) {
         throw new InvalidKeyException("Key cannot be null");
      }

      if (key.getAlgorithm().equals(algorithm)) {
         return key;
      }

      byte[] encoded = key.getEncoded();
      if (encoded == null) {
         throw new InvalidKeyException("Key does not support encoding");
      }

      return createKey(encoded);
   }

   /**
    * Creates a SecretKey wrapping the given bytes. Subclasses can override
    * to return a custom SecretKey type (e.g., PBES2SecretKey).
    */
   protected SecretKey createKey(byte[] keyBytes) {
      return new SecretKeySpec(keyBytes, algorithm);
   }
}
