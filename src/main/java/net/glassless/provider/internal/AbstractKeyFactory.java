package net.glassless.provider.internal;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Abstract base for KeyFactory implementations.
 * Provides a shared {@link #engineTranslateKey} that re-encodes keys
 * via {@link #engineGeneratePublic}/{@link #engineGeneratePrivate}.
 */
public abstract class AbstractKeyFactory extends KeyFactorySpi {

   /**
    * Returns {@code true} if the key is already an instance produced by
    * this provider and needs no translation.
    */
   protected abstract boolean isOwnKey(Key key);

   @Override
   protected Key engineTranslateKey(Key key) throws InvalidKeyException {
      if (key == null) {
         throw new InvalidKeyException("Key cannot be null");
      }
      if (isOwnKey(key)) {
         return key;
      }
      if (key instanceof PublicKey) {
         try {
            return engineGeneratePublic(new X509EncodedKeySpec(key.getEncoded()));
         } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate public key", e);
         }
      } else if (key instanceof PrivateKey) {
         try {
            return engineGeneratePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
         } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate private key", e);
         }
      }
      throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
   }
}
