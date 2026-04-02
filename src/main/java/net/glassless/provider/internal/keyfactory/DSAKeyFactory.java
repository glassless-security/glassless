package net.glassless.provider.internal.keyfactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * DSA KeyFactory implementation using OpenSSL.
 * Self-contained: parses keys using OpenSSL, no delegation to other providers.
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
      return key instanceof GlaSSLessDSAPublicKey || key instanceof GlaSSLessDSAPrivateKey;
   }

   private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse DSA public key");
         }
         try {
            DSAParameterSpec params = extractDSAParams(pkey, arena);
            BigInteger y = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "pub", arena);
            return new GlaSSLessDSAPublicKey(y, params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to decode DSA public key", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse DSA private key");
         }
         try {
            return extractDSAPrivateKey(pkey, arena, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to decode DSA private key", ex);
      }
   }

   private PublicKey generatePublicKeyFromSpec(DSAPublicKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("DSA",
            new String[]{"pub", "p", "q", "g"},
            new BigInteger[]{spec.getY(), spec.getP(), spec.getQ(), spec.getG()},
            OpenSSLCrypto.SELECT_PUBLIC_KEY, arena);
         try {
            byte[] encoded = OpenSSLCrypto.exportPublicKey(pkey, arena);
            DSAParameterSpec params = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
            return new GlaSSLessDSAPublicKey(spec.getY(), params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate DSA public key from spec", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromSpec(DSAPrivateKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("DSA",
            new String[]{"priv", "p", "q", "g"},
            new BigInteger[]{spec.getX(), spec.getP(), spec.getQ(), spec.getG()},
            OpenSSLCrypto.SELECT_KEYPAIR, arena);
         try {
            byte[] encoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);
            DSAParameterSpec params = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
            return new GlaSSLessDSAPrivateKey(spec.getX(), params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate DSA private key from spec", ex);
      }
   }

   public static DSAParameterSpec extractDSAParams(MemorySegment pkey, Arena arena) throws Throwable {
      BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p", arena);
      BigInteger q = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "q", arena);
      BigInteger g = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "g", arena);
      return new DSAParameterSpec(p, q, g);
   }

   public static GlaSSLessDSAPrivateKey extractDSAPrivateKey(MemorySegment pkey, Arena arena, byte[] encoded) throws Throwable {
      DSAParameterSpec params = extractDSAParams(pkey, arena);
      BigInteger x = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "priv", arena);
      return new GlaSSLessDSAPrivateKey(x, params, encoded);
   }
}
