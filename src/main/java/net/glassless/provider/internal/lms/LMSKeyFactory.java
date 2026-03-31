package net.glassless.provider.internal.lms;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.AbstractKeyFactory;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyFactory for LMS (Leighton-Micali Signature) keys.
 * Only public keys are supported since LMS is verification-only.
 */
public class LMSKeyFactory extends AbstractKeyFactory {

   @Override
   protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof X509EncodedKeySpec x509Spec) {
         return generatePublicFromEncoded(x509Spec.getEncoded());
      }
      throw new InvalidKeySpecException("Unsupported key spec: " +
         (keySpec == null ? "null" : keySpec.getClass().getName()));
   }

   @Override
   protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      throw new InvalidKeySpecException("LMS private keys are not supported. " +
         "LMS is a stateful signature scheme; only public keys for verification are available.");
   }

   @Override
   @SuppressWarnings("unchecked")
   protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
      if (key instanceof GlaSSLessLMSPublicKey pubKey) {
         if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            return (T) new X509EncodedKeySpec(pubKey.getEncoded());
         }
      }
      throw new InvalidKeySpecException("Unsupported key type or spec: " +
         (key == null ? "null" : key.getClass().getName()) + " / " +
         (keySpec == null ? "null" : keySpec.getName()));
   }

   @Override
   protected boolean isOwnKey(Key key) {
      return key instanceof GlaSSLessLMSPublicKey;
   }

   private PublicKey generatePublicFromEncoded(byte[] encoded) throws InvalidKeySpecException {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment pkey = OpenSSLCrypto.loadPublicKey(encoded, arena);
         if (pkey.equals(MemorySegment.NULL)) {
            throw new InvalidKeySpecException("Failed to parse LMS public key");
         }

         try {
            return new GlaSSLessLMSPublicKey(encoded);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pkey);
         }
      } catch (InvalidKeySpecException e) {
         throw e;
      } catch (Throwable e) {
         throw new InvalidKeySpecException("Failed to generate LMS public key", e);
      }
   }
}
