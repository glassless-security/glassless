package net.glassless.provider.internal.keyfactory;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;

/**
 * DSA KeyFactory implementation.
 * Supports conversion between DSA keys and various key specifications.
 */
public class DSAKeyFactory extends AbstractKeyFactory {

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof X509EncodedKeySpec x509Spec) {
         return generatePublicKeyFromEncoded(x509Spec.getEncoded());

      } else if (keySpec instanceof DSAPublicKeySpec dsaSpec) {
         return generatePublicKeyFromSpec(dsaSpec);

      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
         return generatePrivateKeyFromEncoded(pkcs8Spec.getEncoded());

      } else if (keySpec instanceof DSAPrivateKeySpec dsaSpec) {
         return generatePrivateKeyFromSpec(dsaSpec);

      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
      switch (key) {
         case null -> throw new InvalidKeySpecException("Key cannot be null");
         case DSAPublicKey dsaKey -> {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new X509EncodedKeySpec(encoded);

            } else if (DSAPublicKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new DSAPublicKeySpec(
                  dsaKey.getY(),
                  dsaKey.getParams().getP(),
                  dsaKey.getParams().getQ(),
                  dsaKey.getParams().getG()
               );

            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for DSA public key: " + keySpec.getName());
            }
         }
         case DSAPrivateKey dsaKey -> {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new PKCS8EncodedKeySpec(encoded);

            } else if (DSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new DSAPrivateKeySpec(
                  dsaKey.getX(),
                  dsaKey.getParams().getP(),
                  dsaKey.getParams().getQ(),
                  dsaKey.getParams().getG()
               );

            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for DSA private key: " + keySpec.getName());
            }
         }
         default -> throw new InvalidKeySpecException("Key is not a DSA key");
      }

   }

   @Override
   protected boolean isOwnKey(Key key) {
      return false;
   }

   private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DSA");
         return kf.generatePublic(new X509EncodedKeySpec(encoded));
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to decode DSA public key", e);
      }
   }

   private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DSA");
         return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to decode DSA private key", e);
      }
   }

   private PublicKey generatePublicKeyFromSpec(DSAPublicKeySpec spec) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DSA");
         return kf.generatePublic(spec);
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to generate DSA public key from spec", e);
      }
   }

   private PrivateKey generatePrivateKeyFromSpec(DSAPrivateKeySpec spec) throws InvalidKeySpecException {
      try {
         java.security.KeyFactory kf = java.security.KeyFactory.getInstance("DSA");
         return kf.generatePrivate(spec);
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to generate DSA private key from spec", e);
      }
   }
}
