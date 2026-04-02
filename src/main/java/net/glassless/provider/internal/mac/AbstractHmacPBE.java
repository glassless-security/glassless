package net.glassless.provider.internal.mac;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for PBE-based HMAC implementations.
 * Derives the HMAC key from a password using PBKDF2, then delegates to {@link AbstractHmac}.
 */
public abstract class AbstractHmacPBE extends AbstractHmac {

   private final String kdfDigestName; // Digest used for PBKDF2
   private final int derivedKeyLength;

   protected AbstractHmacPBE(String digestName, String kdfDigestName, int macLength, int derivedKeyLength) {
      super(digestName, macLength);
      this.kdfDigestName = kdfDigestName;
      this.derivedKeyLength = derivedKeyLength;
   }

   @Override
   protected byte[] extractKeyBytes(Key key, AlgorithmParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
      // Extract password from key
      char[] password;
      if (key instanceof PBEKey pbeKey) {
         password = pbeKey.getPassword();
      } else if (key instanceof SecretKey) {
         byte[] keyBytes = key.getEncoded();
         if (keyBytes == null) {
            throw new InvalidKeyException("Key encoding not available");
         }
         password = new String(keyBytes, java.nio.charset.StandardCharsets.UTF_8).toCharArray();
      } else {
         throw new InvalidKeyException("Key must be a PBEKey or SecretKey");
      }

      // Extract salt and iteration count from params
      if (!(params instanceof PBEParameterSpec pbeParams)) {
         throw new InvalidAlgorithmParameterException("PBEParameterSpec required");
      }

      byte[] salt = pbeParams.getSalt();
      int iterationCount = pbeParams.getIterationCount();

      try {
         return OpenSSLCrypto.PKCS5_PBKDF2_HMAC(password, salt, iterationCount, kdfDigestName,
            derivedKeyLength, arena);
      } catch (Throwable e) {
         throw new InvalidKeyException("PBKDF2 key derivation failed", e);
      }
   }
}
