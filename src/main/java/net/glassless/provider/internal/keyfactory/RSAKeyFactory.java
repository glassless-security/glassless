package net.glassless.provider.internal.keyfactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * RSA KeyFactory implementation using OpenSSL.
 * Self-contained: parses keys using OpenSSL, no delegation to other providers.
 */
public class RSAKeyFactory extends AbstractKeyFactory {

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof X509EncodedKeySpec x509Spec) {
         return generatePublicKeyFromEncoded(x509Spec.getEncoded());
      } else if (keySpec instanceof RSAPublicKeySpec rsaSpec) {
         return generatePublicKeyFromSpec(rsaSpec);
      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      return switch (keySpec) {
         case PKCS8EncodedKeySpec pkcs8Spec -> generatePrivateKeyFromEncoded(pkcs8Spec.getEncoded());
         case RSAPrivateCrtKeySpec rsaCrtSpec -> generatePrivateKeyFromCrtSpec(rsaCrtSpec);
         case RSAPrivateKeySpec rsaSpec -> generatePrivateKeyFromSpec(rsaSpec);
         default -> throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      };
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
      switch (key) {
         case null -> throw new InvalidKeySpecException("Key cannot be null");
         case RSAPublicKey rsaKey -> {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new X509EncodedKeySpec(encoded);
            } else if (RSAPublicKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());
            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for RSA public key: " + keySpec.getName());
            }
         }
         case RSAPrivateCrtKey rsaCrtKey -> {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new PKCS8EncodedKeySpec(encoded);
            } else if (RSAPrivateCrtKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new RSAPrivateCrtKeySpec(
                  rsaCrtKey.getModulus(),
                  rsaCrtKey.getPublicExponent(),
                  rsaCrtKey.getPrivateExponent(),
                  rsaCrtKey.getPrimeP(),
                  rsaCrtKey.getPrimeQ(),
                  rsaCrtKey.getPrimeExponentP(),
                  rsaCrtKey.getPrimeExponentQ(),
                  rsaCrtKey.getCrtCoefficient()
               );
            } else if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new RSAPrivateKeySpec(rsaCrtKey.getModulus(), rsaCrtKey.getPrivateExponent());
            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for RSA private CRT key: " + keySpec.getName());
            }
         }
         case RSAPrivateKey rsaKey -> {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new PKCS8EncodedKeySpec(encoded);
            } else if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new RSAPrivateKeySpec(rsaKey.getModulus(), rsaKey.getPrivateExponent());
            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for RSA private key: " + keySpec.getName());
            }
         }
         default -> throw new InvalidKeySpecException("Key is not an RSA key");
      }
   }

   @Override
   protected boolean isOwnKey(Key key) {
      return key instanceof GlaSSLessRSAPublicKey || key instanceof GlaSSLessRSAPrivateKey;
   }

   private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse RSA public key");
         }
         try {
            BigInteger n = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "n", arena);
            BigInteger e = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "e", arena);
            return new GlaSSLessRSAPublicKey(n, e, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to decode RSA public key", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse RSA private key");
         }
         try {
            return extractRSAPrivateKey(pkey, arena, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to decode RSA private key", ex);
      }
   }

   private PublicKey generatePublicKeyFromSpec(RSAPublicKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("RSA",
            new String[]{"n", "e"},
            new BigInteger[]{spec.getModulus(), spec.getPublicExponent()},
            OpenSSLCrypto.SELECT_PUBLIC_KEY, arena);
         try {
            byte[] encoded = OpenSSLCrypto.exportPublicKey(pkey, arena);
            return new GlaSSLessRSAPublicKey(spec.getModulus(), spec.getPublicExponent(), encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate RSA public key from spec", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromSpec(RSAPrivateKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         // RSAPrivateKeySpec only has n and d (no public exponent or CRT params)
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("RSA",
            new String[]{"n", "d"},
            new BigInteger[]{spec.getModulus(), spec.getPrivateExponent()},
            OpenSSLCrypto.SELECT_KEYPAIR, arena);
         try {
            byte[] encoded;
            try {
               encoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);
            } catch (Throwable e) {
               encoded = null;
            }
            return new GlaSSLessRSAPrivateKey(
               spec.getModulus(), null, spec.getPrivateExponent(),
               null, null, null, null, null, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate RSA private key from spec", ex);
      }
   }

   private PrivateKey generatePrivateKeyFromCrtSpec(RSAPrivateCrtKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.createKeyFromBNParams("RSA",
            new String[]{"n", "e", "d", "rsa-factor1", "rsa-factor2",
               "rsa-exponent1", "rsa-exponent2", "rsa-coefficient1"},
            new BigInteger[]{spec.getModulus(), spec.getPublicExponent(), spec.getPrivateExponent(),
               spec.getPrimeP(), spec.getPrimeQ(),
               spec.getPrimeExponentP(), spec.getPrimeExponentQ(), spec.getCrtCoefficient()},
            OpenSSLCrypto.SELECT_KEYPAIR, arena);
         try {
            byte[] encoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);
            return new GlaSSLessRSAPrivateKey(
               spec.getModulus(), spec.getPublicExponent(), spec.getPrivateExponent(),
               spec.getPrimeP(), spec.getPrimeQ(),
               spec.getPrimeExponentP(), spec.getPrimeExponentQ(), spec.getCrtCoefficient(),
               encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (Throwable ex) {
         throw new InvalidKeySpecException("Failed to generate RSA private CRT key from spec", ex);
      }
   }

   /**
    * Extracts RSA private key components from an EVP_PKEY.
    * Attempts to extract CRT parameters; falls back to basic n/d if CRT params unavailable.
    */
   public static GlaSSLessRSAPrivateKey extractRSAPrivateKey(MemorySegment pkey, Arena arena, byte[] encoded) throws Throwable {
      BigInteger n = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "n", arena);
      BigInteger e = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "e", arena);
      BigInteger d = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "d", arena);

      BigInteger p = null, q = null, dp = null, dq = null, qInv = null;
      try {
         p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "rsa-factor1", arena);
         q = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "rsa-factor2", arena);
         dp = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "rsa-exponent1", arena);
         dq = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "rsa-exponent2", arena);
         qInv = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "rsa-coefficient1", arena);
      } catch (IllegalStateException ignored) {
         // CRT params not available — return basic RSA private key
      }

      return new GlaSSLessRSAPrivateKey(n, e, d, p, q, dp, dq, qInv, encoded);
   }
}
