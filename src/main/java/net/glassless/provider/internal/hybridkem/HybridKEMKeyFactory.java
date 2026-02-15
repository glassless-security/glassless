package net.glassless.provider.internal.hybridkem;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactory for hybrid KEM keys.
 * Supports X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
 *
 * <p>Note: Hybrid KEM keys use a custom encoding format since OpenSSL doesn't provide
 * standard ASN.1 encoders for these key types yet. The encoded format starts with
 * magic bytes "HKEM" followed by the key data.
 */
public class HybridKEMKeyFactory extends KeyFactorySpi {

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof EncodedKeySpec encodedSpec) {
         return generatePublicFromEncoded(encodedSpec.getEncoded());
      }
      throw new InvalidKeySpecException("Unsupported key spec: " +
         (keySpec == null ? "null" : keySpec.getClass().getName()) +
         ". Use X509EncodedKeySpec with hybrid KEM encoded bytes.");
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof EncodedKeySpec encodedSpec) {
         return generatePrivateFromEncoded(encodedSpec.getEncoded());
      }
      throw new InvalidKeySpecException("Unsupported key spec: " +
         (keySpec == null ? "null" : keySpec.getClass().getName()) +
         ". Use PKCS8EncodedKeySpec with hybrid KEM encoded bytes.");
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
         throws InvalidKeySpecException {
      if (key instanceof GlaSSLessHybridKEMPublicKey pubKey) {
         if (X509EncodedKeySpec.class.isAssignableFrom(keySpec) ||
             EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            return (T) new X509EncodedKeySpec(pubKey.getEncoded());
         }
      } else if (key instanceof GlaSSLessHybridKEMPrivateKey privKey) {
         if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec) ||
             EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            return (T) new PKCS8EncodedKeySpec(privKey.getEncoded());
         }
      }
      throw new InvalidKeySpecException("Unsupported key type or spec: " +
         (key == null ? "null" : key.getClass().getName()) + " / " +
         (keySpec == null ? "null" : keySpec.getName()));
   }

   @Override
   protected Key engineTranslateKey(Key key) throws InvalidKeyException {
      if (key instanceof GlaSSLessHybridKEMPublicKey || key instanceof GlaSSLessHybridKEMPrivateKey) {
         return key;
      }

      // Cannot translate non-hybrid KEM keys
      throw new InvalidKeyException("Cannot translate key type: " +
         (key == null ? "null" : key.getClass().getName()) +
         ". Hybrid KEM keys must be generated using the GlaSSLess provider.");
   }

   private PublicKey generatePublicFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try {
         // Decode from the custom format
         return GlaSSLessHybridKEMPublicKey.decode(encoded);
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to parse hybrid KEM public key: " + e.getMessage(), e);
      }
   }

   private PrivateKey generatePrivateFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try {
         // Decode from the custom format
         return GlaSSLessHybridKEMPrivateKey.decode(encoded);
      } catch (Exception e) {
         throw new InvalidKeySpecException("Failed to parse hybrid KEM private key: " + e.getMessage(), e);
      }
   }
}
