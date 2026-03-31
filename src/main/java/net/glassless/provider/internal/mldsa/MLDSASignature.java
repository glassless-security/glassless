package net.glassless.provider.internal.mldsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.glassless.provider.internal.AbstractSingleShotSignature;

/**
 * ML-DSA Signature implementation using OpenSSL.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.
 *
 * <p>ML-DSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class MLDSASignature extends AbstractSingleShotSignature {

   private final String expectedVariant;  // null means accept any ML-DSA variant

   public MLDSASignature() {
      this(null);
   }

   protected MLDSASignature(String expectedVariant) {
      super("ML-DSA");
      this.expectedVariant = expectedVariant;
   }

   @Override
   protected void validateAndInitSign(PrivateKey privateKey) throws InvalidKeyException {
      if (privateKey == null) {
         throw new InvalidKeyException("Private key cannot be null");
      }

      String keyAlgorithm = privateKey.getAlgorithm();
      if (!keyAlgorithm.startsWith("ML-DSA") && !keyAlgorithm.equals("MLDSA")) {
         throw new InvalidKeyException("ML-DSA private key required, got: " + keyAlgorithm);
      }

      if (expectedVariant != null) {
         String normalizedKey = keyAlgorithm.replace("-", "").replace("_", "").toUpperCase();
         String normalizedExpected = expectedVariant.replace("-", "").replace("_", "").toUpperCase();
         if (!normalizedKey.contains(normalizedExpected.replace("MLDSA", ""))) {
            throw new InvalidKeyException("Key variant " + keyAlgorithm +
               " does not match expected variant " + expectedVariant);
         }
      }

      this.privateKeyEncoded = privateKey.getEncoded();
      if (this.privateKeyEncoded == null) {
         throw new InvalidKeyException("Private key encoding is null");
      }
   }

   @Override
   protected void validateAndInitVerify(PublicKey publicKey) throws InvalidKeyException {
      if (publicKey == null) {
         throw new InvalidKeyException("Public key cannot be null");
      }

      String keyAlgorithm = publicKey.getAlgorithm();
      if (!keyAlgorithm.startsWith("ML-DSA") && !keyAlgorithm.equals("MLDSA")) {
         throw new InvalidKeyException("ML-DSA public key required, got: " + keyAlgorithm);
      }

      if (expectedVariant != null) {
         String normalizedKey = keyAlgorithm.replace("-", "").replace("_", "").toUpperCase();
         String normalizedExpected = expectedVariant.replace("-", "").replace("_", "").toUpperCase();
         if (!normalizedKey.contains(normalizedExpected.replace("MLDSA", ""))) {
            throw new InvalidKeyException("Key variant " + keyAlgorithm +
               " does not match expected variant " + expectedVariant);
         }
      }

      this.publicKeyEncoded = publicKey.getEncoded();
      if (this.publicKeyEncoded == null) {
         throw new InvalidKeyException("Public key encoding is null");
      }
   }
}
