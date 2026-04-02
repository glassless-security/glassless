package net.glassless.provider.internal.keyfactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ConcurrentHashMap;

import net.glassless.provider.internal.AbstractKeyFactory;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * EC (Elliptic Curve) KeyFactory implementation.
 * Self-contained: parses keys using OpenSSL, no delegation to other providers.
 */
public class ECKeyFactory extends AbstractKeyFactory {

   // Cache curve parameters by field size to avoid redundant OpenSSL calls
   private static final ConcurrentHashMap<Integer, ECParameterSpec> PARAMS_CACHE = new ConcurrentHashMap<>();

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof X509EncodedKeySpec x509Spec) {
         return generatePublicKeyFromEncoded(x509Spec.getEncoded());
      } else if (keySpec instanceof ECPublicKeySpec ecSpec) {
         return generatePublicKeyFromSpec(ecSpec);
      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
         return generatePrivateKeyFromEncoded(pkcs8Spec.getEncoded());
      } else if (keySpec instanceof ECPrivateKeySpec ecSpec) {
         return generatePrivateKeyFromSpec(ecSpec);
      } else {
         throw new InvalidKeySpecException("Unsupported KeySpec type: " + keySpec.getClass().getName());
      }
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
      switch (key) {
         case null -> throw new InvalidKeySpecException("Key cannot be null");
         case ECPublicKey ecKey -> {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new X509EncodedKeySpec(encoded);
            } else if (ECPublicKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new ECPublicKeySpec(ecKey.getW(), ecKey.getParams());
            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for EC public key: " + keySpec.getName());
            }
         }
         case ECPrivateKey ecKey -> {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
               byte[] encoded = key.getEncoded();
               if (encoded == null) {
                  throw new InvalidKeySpecException("Key does not support encoding");
               }
               return (T) new PKCS8EncodedKeySpec(encoded);
            } else if (ECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
               return (T) new ECPrivateKeySpec(ecKey.getS(), ecKey.getParams());
            } else {
               throw new InvalidKeySpecException("Unsupported KeySpec for EC private key: " + keySpec.getName());
            }
         }
         default -> throw new InvalidKeySpecException("Key is not an EC key");
      }
   }

   @Override
   protected boolean isOwnKey(Key key) {
      return key instanceof GlaSSLessECPublicKey || key instanceof GlaSSLessECPrivateKey;
   }

   private PublicKey generatePublicKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse EC public key");
         }
         try {
            ECParameterSpec params = getCachedParams(pkey, arena);
            ECPoint w = OpenSSLCrypto.extractECPublicPoint(pkey, arena);
            return new GlaSSLessECPublicKey(w, params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to decode EC public key", e);
      }
   }

   private PrivateKey generatePrivateKeyFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse EC private key");
         }
         try {
            ECParameterSpec params = getCachedParams(pkey, arena);
            BigInteger s = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "priv", arena);
            return new GlaSSLessECPrivateKey(s, params, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to decode EC private key", e);
      }
   }

   private static ECParameterSpec getCachedParams(MemorySegment pkey, Arena arena) throws Throwable {
      // Get field size from the key's "p" parameter to look up cache without full extraction
      BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p", arena);
      int fieldSize = p.bitLength();
      ECParameterSpec cached = PARAMS_CACHE.get(fieldSize);
      if (cached != null) {
         return cached;
      }
      ECParameterSpec params = OpenSSLCrypto.extractECParameterSpec(pkey, arena);
      PARAMS_CACHE.putIfAbsent(fieldSize, params);
      return params;
   }

   private PublicKey generatePublicKeyFromSpec(ECPublicKeySpec spec) throws InvalidKeySpecException {
      // We need to create an encoded key from the spec components
      // Re-encode via OpenSSL by generating a key with the right curve, then importing
      // For now, we construct from the spec directly — the key won't have an encoding
      // unless we round-trip through OpenSSL.
      // The simplest approach: use the spec values directly.
      return new GlaSSLessECPublicKey(spec.getW(), spec.getParams(), encodeECPublicKey(spec));
   }

   private PrivateKey generatePrivateKeyFromSpec(ECPrivateKeySpec spec) throws InvalidKeySpecException {
      // ECPrivateKeySpec only has S and params — no public key.
      // Try to produce PKCS8 encoding; if not possible, create key without encoding.
      byte[] encoded;
      try {
         encoded = encodeECPrivateKey(spec);
      } catch (InvalidKeySpecException e) {
         encoded = null;
      }
      return new GlaSSLessECPrivateKey(spec.getS(), spec.getParams(), encoded);
   }

   /**
    * Encodes an EC public key spec to X.509/SubjectPublicKeyInfo DER format.
    * Uses OpenSSL to do the encoding by creating a key from components.
    */
   private byte[] encodeECPublicKey(ECPublicKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         // Determine curve name from field size
         String curveName = getCurveNameFromFieldSize(spec.getParams().getCurve().getField().getFieldSize());

         // Generate a temp key for this curve, then set the public point
         // Actually, the simplest approach: build the uncompressed point, use EVP_PKEY_fromdata
         // For now, create the key via keygen and export — but this gives us a DIFFERENT key
         // Better approach: use OpenSSL's EC key import

         // Build uncompressed point: 04 || x || y
         ECPoint w = spec.getW();
         int fieldSize = (spec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
         byte[] x = toFixedLengthBytes(w.getAffineX(), fieldSize);
         byte[] y = toFixedLengthBytes(w.getAffineY(), fieldSize);
         byte[] uncompressed = new byte[1 + x.length + y.length];
         uncompressed[0] = 0x04;
         System.arraycopy(x, 0, uncompressed, 1, x.length);
         System.arraycopy(y, 0, uncompressed, 1 + x.length, y.length);

         // Use OSSL_PARAM-based import to create EVP_PKEY from curve + public point
         MemorySegment pkey = OpenSSLCrypto.createECPublicKeyFromPoint(curveName, uncompressed, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to create EC public key from spec");
         }
         try {
            return OpenSSLCrypto.exportPublicKey(pkey, arena);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to encode EC public key", e);
      }
   }

   /**
    * Encodes an EC private key spec to PKCS#8 DER format.
    */
   private byte[] encodeECPrivateKey(ECPrivateKeySpec spec) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         String curveName = getCurveNameFromFieldSize(spec.getParams().getCurve().getField().getFieldSize());

         MemorySegment pkey = OpenSSLCrypto.createECPrivateKeyFromScalar(curveName, spec.getS(), arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to create EC private key from spec");
         }
         try {
            return OpenSSLCrypto.exportPrivateKey(pkey, arena);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to encode EC private key", e);
      }
   }

   private static String getCurveNameFromFieldSize(int fieldSize) throws InvalidKeySpecException {
      return switch (fieldSize) {
         case 256 -> "P-256";
         case 384 -> "P-384";
         case 521 -> "P-521";
         case 224 -> "P-224";
         default -> throw new InvalidKeySpecException("Unsupported EC field size: " + fieldSize);
      };
   }

   private static byte[] toFixedLengthBytes(BigInteger value, int length) {
      byte[] bytes = value.toByteArray();
      if (bytes.length == length) {
         return bytes;
      } else if (bytes.length > length) {
         // Strip leading zero byte (sign extension)
         byte[] trimmed = new byte[length];
         System.arraycopy(bytes, bytes.length - length, trimmed, 0, length);
         return trimmed;
      } else {
         // Pad with leading zeros
         byte[] padded = new byte[length];
         System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
         return padded;
      }
   }
}
