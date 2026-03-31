package net.glassless.provider.internal.keyfactory;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;

/**
 * DH (Diffie-Hellman) KeyFactory implementation.
 * Supports conversion between DH keys and various key specifications.
 */
public class DHKeyFactory extends AbstractKeyFactory {

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof X509EncodedKeySpec x509Spec) {
         return generatePublicKeyFromEncoded(x509Spec.getEncoded());

      } else if (keySpec instanceof DHPublicKeySpec dhSpec) {
         return generatePublicKeyFromSpec(dhSpec);

      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
         return generatePrivateKeyFromEncoded(pkcs8Spec.getEncoded());

      } else if (keySpec instanceof DHPrivateKeySpec dhSpec) {
         return generatePrivateKeyFromSpec(dhSpec);

      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
      switch (key) {
         case null -> throw new InvalidKeySpecException("Key cannot be null");
         case DHPublicKey dhKey -> {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new X509EncodedKeySpec(encoded);

            } else if (DHPublicKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new DHPublicKeySpec(
                  dhKey.getY(),
                  dhKey.getParams().getP(),
                  dhKey.getParams().getG()
               );

            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for DH public key: " + keySpec.getName());
            }
         }
         case DHPrivateKey dhKey -> {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new PKCS8EncodedKeySpec(encoded);

            } else if (DHPrivateKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new DHPrivateKeySpec(
                  dhKey.getX(),
                  dhKey.getParams().getP(),
                  dhKey.getParams().getG()
               );

            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for DH private key: " + keySpec.getName());
            }
         }
         default -> throw new InvalidKeySpecException("Key is not a DH key");
      }

   }

   @Override
   protected boolean isOwnKey(Key key) {
      return false;
   }

   private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DH");
         return kf.generatePublic(new X509EncodedKeySpec(encoded));
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to decode DH public key", e);
      }
   }

   private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DH");
         return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to decode DH private key", e);
      }
   }

   private PublicKey generatePublicKeyFromSpec(DHPublicKeySpec spec) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DH");
         return kf.generatePublic(spec);
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to generate DH public key from spec", e);
      }
   }

   private PrivateKey generatePrivateKeyFromSpec(DHPrivateKeySpec spec) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DH");
         return kf.generatePrivate(spec);
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to generate DH private key from spec", e);
      }
   }
}
