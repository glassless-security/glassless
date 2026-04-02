package net.glassless.provider.internal.keyfactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * DH (Diffie-Hellman) KeyFactory implementation using OpenSSL.
 * Self-contained: parses keys using OpenSSL, no delegation to other providers.
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
      return key instanceof GlaSSLessDHPublicKey || key instanceof GlaSSLessDHPrivateKey;
   }

   private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse DH public key");
         }
         try {
            DHParameterSpec params = extractDHParams(pkey, arena);
            BigInteger y = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "pub", arena);
            return new GlaSSLessDHPublicKey(y, params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to decode DH public key", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse DH private key");
         }
         try {
            return extractDHPrivateKey(pkey, arena, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to decode DH private key", ex);
      }
   }

   private PublicKey generatePublicKeyFromSpec(DHPublicKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("DH",
            new String[]{"pub", "p", "g"},
            new BigInteger[]{spec.getY(), spec.getP(), spec.getG()},
            OpenSSLCrypto.SELECT_PUBLIC_KEY, arena);
         try {
            byte[] encoded = OpenSSLCrypto.exportPublicKey(pkey, arena);
            DHParameterSpec params = new DHParameterSpec(spec.getP(), spec.getG());
            return new GlaSSLessDHPublicKey(spec.getY(), params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate DH public key from spec", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromSpec(DHPrivateKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("DH",
            new String[]{"priv", "p", "g"},
            new BigInteger[]{spec.getX(), spec.getP(), spec.getG()},
            OpenSSLCrypto.SELECT_KEYPAIR, arena);
         try {
            byte[] encoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);
            DHParameterSpec params = new DHParameterSpec(spec.getP(), spec.getG());
            return new GlaSSLessDHPrivateKey(spec.getX(), params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate DH private key from spec", ex);
      }
   }

   public static DHParameterSpec extractDHParams(MemorySegment pkey, Arena arena) throws Throwable {
      BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p", arena);
      BigInteger g = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "g", arena);
      return new DHParameterSpec(p, g);
   }

   public static GlaSSLessDHPrivateKey extractDHPrivateKey(MemorySegment pkey, Arena arena, byte[] encoded) throws Throwable {
      DHParameterSpec params = extractDHParams(pkey, arena);
      BigInteger x = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "priv", arena);
      return new GlaSSLessDHPrivateKey(x, params, encoded);
   }
}
