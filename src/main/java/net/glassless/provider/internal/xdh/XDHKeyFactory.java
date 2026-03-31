package net.glassless.provider.internal.xdh;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;
import net.glassless.provider.internal.KeyEncodingUtils;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyFactory for XDH keys (X25519 and X448).
 */
public class XDHKeyFactory extends AbstractKeyFactory {

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof X509EncodedKeySpec x509Spec) {
         return generatePublicFromEncoded(x509Spec.getEncoded());
      } else if (keySpec instanceof XECPublicKeySpec xecSpec) {
         return generatePublicFromSpec(xecSpec);
      } else {
         throw new InvalidKeySpecException("Unsupported key spec: " +
            (keySpec == null ? "null" : keySpec.getClass().getName()));
      }
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof PKCS8EncodedKeySpec pkcs8Spec) {
         return generatePrivateFromEncoded(pkcs8Spec.getEncoded());
      } else if (keySpec instanceof XECPrivateKeySpec xecSpec) {
         return generatePrivateFromSpec(xecSpec);
      } else {
         throw new InvalidKeySpecException("Unsupported key spec: " +
            (keySpec == null ? "null" : keySpec.getClass().getName()));
      }
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
      if (key instanceof XECPublicKey pubKey) {
         if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            return (T) new X509EncodedKeySpec(pubKey.getEncoded());
         } else if (XECPublicKeySpec.class.isAssignableFrom(keySpec)) {
            return (T) new XECPublicKeySpec(pubKey.getParams(), pubKey.getU());
         }
      } else if (key instanceof XECPrivateKey privKey) {
         if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            return (T) new PKCS8EncodedKeySpec(privKey.getEncoded());
         } else if (XECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
            if (privKey.getScalar().isPresent()) {
               return (T) new XECPrivateKeySpec(privKey.getParams(), privKey.getScalar().get());
            }
         }
      }
      throw new InvalidKeySpecException("Unsupported key type or spec: " +
         (key == null ? "null" : key.getClass().getName()) + " / " +
         (keySpec == null ? "null" : keySpec.getName()));
   }

   @Override
   protected boolean isOwnKey(Key key) {
      return key instanceof GlaSSLessXECPublicKey || key instanceof GlaSSLessXECPrivateKey;
   }

   private PublicKey generatePublicFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse XDH public key");
         }

         try {
            NamedParameterSpec params = detectCurveFromPublicKey(encoded);
            int keyLen = params.getName().equalsIgnoreCase("X25519") ? 32 : 56;

            byte[] rawKey = new byte[keyLen];
            System.arraycopy(encoded, encoded.length - keyLen, rawKey, 0, keyLen);

            BigInteger u = createUCoordinate(rawKey);

            return new GlaSSLessXECPublicKey(params, u, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to generate XDH public key", e);
      }
   }

   private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse XDH private key");
         }

         try {
            NamedParameterSpec params = detectCurveFromPrivateKey(encoded);
            int keyLen = params.getName().equalsIgnoreCase("X25519") ? 32 : 56;

            byte[] rawKey = new byte[keyLen];
            System.arraycopy(encoded, encoded.length - keyLen, rawKey, 0, keyLen);

            return new GlaSSLessXECPrivateKey(params, rawKey, encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to generate XDH private key", e);
      }
   }

   private PublicKey generatePublicFromSpec(XECPublicKeySpec spec) throws InvalidKeySpecException {
      if (!(spec.getParams() instanceof NamedParameterSpec params)) {
         throw new InvalidKeySpecException("NamedParameterSpec required");
      }

      BigInteger u = spec.getU();
      byte[] rawKey = encodeUCoordinate(u, params);
      byte[] encoded = createX509Encoding(params, rawKey);

      return new GlaSSLessXECPublicKey(params, u, encoded);
   }

   private PrivateKey generatePrivateFromSpec(XECPrivateKeySpec spec) throws InvalidKeySpecException {
      if (!(spec.getParams() instanceof NamedParameterSpec params)) {
         throw new InvalidKeySpecException("NamedParameterSpec required");
      }

      byte[] scalar = spec.getScalar();
      byte[] encoded = createPKCS8Encoding(params, scalar);

      return new GlaSSLessXECPrivateKey(params, scalar, encoded);
   }

   private NamedParameterSpec detectCurveFromPublicKey(byte[] encoded) {
      // X25519 X.509 encoded is 44 bytes, X448 is 68 bytes
      if (encoded.length == 44) {
         return NamedParameterSpec.X25519;
      } else if (encoded.length == 68) {
         return NamedParameterSpec.X448;
      }
      return checkOid(encoded);
   }

   private NamedParameterSpec detectCurveFromPrivateKey(byte[] encoded) {
      // X25519 PKCS#8 encoded is 48 bytes, X448 is 72 bytes
      if (encoded.length == 48) {
         return NamedParameterSpec.X25519;
      } else if (encoded.length == 72) {
         return NamedParameterSpec.X448;
      }
      // Check OID
      return checkOid(encoded);
   }

   // Check OID: X25519 OID: 1.3.101.110 (06 03 2B 65 6E), X448 OID: 1.3.101.111 (06 03 2B 65 6F)
   private NamedParameterSpec checkOid(byte[] encoded) {
      for (int i = 0; i < encoded.length - 4; i++) {
         if (encoded[i] == 0x06 && encoded[i + 1] == 0x03 &&
            encoded[i + 2] == 0x2B && encoded[i + 3] == 0x65) {
            if (encoded[i + 4] == 0x6E) return NamedParameterSpec.X25519;
            if (encoded[i + 4] == 0x6F) return NamedParameterSpec.X448;
         }
      }
      throw new ProviderException("Unable to detect XDH curve from encoded key");
   }

   private BigInteger createUCoordinate(byte[] raw) {
      // XDH uses little-endian encoding
      byte[] reversed = new byte[raw.length + 1];
      reversed[0] = 0;  // Ensure positive
      for (int i = 0; i < raw.length; i++) {
         reversed[i + 1] = raw[raw.length - 1 - i];
      }
      return new BigInteger(reversed);
   }

   private byte[] encodeUCoordinate(BigInteger u, NamedParameterSpec params) {
      int keyLen = params.getName().equalsIgnoreCase("X25519") ? 32 : 56;
      byte[] uBytes = u.toByteArray();

      // Convert to little-endian and fit to key length
      byte[] raw = new byte[keyLen];
      int srcOffset = uBytes[0] == 0 ? 1 : 0;
      int srcLen = uBytes.length - srcOffset;

      // Reverse into raw (little-endian)
      for (int i = 0; i < srcLen && i < keyLen; i++) {
         raw[i] = uBytes[uBytes.length - 1 - i];
      }

      return raw;
   }

   private byte[] getOid(NamedParameterSpec params) {
      if (params.getName().equalsIgnoreCase("X25519")) {
         return new byte[]{0x06, 0x03, 0x2B, 0x65, 0x6E};  // 1.3.101.110
      } else {
         return new byte[]{0x06, 0x03, 0x2B, 0x65, 0x6F};  // 1.3.101.111
      }
   }

   private byte[] createX509Encoding(NamedParameterSpec params, byte[] rawKey) {
      return KeyEncodingUtils.createX509Encoding(getOid(params), rawKey);
   }

   private byte[] createPKCS8Encoding(NamedParameterSpec params, byte[] keyBytes) {
      return KeyEncodingUtils.createPKCS8Encoding(getOid(params), keyBytes);
   }
}
