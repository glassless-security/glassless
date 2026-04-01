package net.glassless.provider.internal.slhdsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Locale;

import net.glassless.provider.internal.AbstractSingleShotSignature;

/**
 * SLH-DSA Signature implementation using OpenSSL.
 * Supports all 12 SLH-DSA variants.
 *
 * <p>SLH-DSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class SLHDSASignature extends AbstractSingleShotSignature {

   private final String expectedVariant;  // null means accept any SLH-DSA variant

   public SLHDSASignature() {
      this(null);
   }

   protected SLHDSASignature(String expectedVariant) {
      super("SLH-DSA");
      this.expectedVariant = expectedVariant;
   }

   @Override
   protected void validateAndInitSign(PrivateKey privateKey) throws InvalidKeyException {
      if (privateKey == null) {
         throw new InvalidKeyException("Private key cannot be null");
      }

      String keyAlgorithm = privateKey.getAlgorithm();
      if (!keyAlgorithm.startsWith("SLH-DSA") && !keyAlgorithm.equals("SLHDSA")) {
         throw new InvalidKeyException("SLH-DSA private key required, got: " + keyAlgorithm);
      }

      if (expectedVariant != null) {
         String normalizedKey = normalizeVariant(keyAlgorithm);
         String normalizedExpected = normalizeVariant(expectedVariant);
         if (!normalizedKey.equals(normalizedExpected)) {
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
      if (!keyAlgorithm.startsWith("SLH-DSA") && !keyAlgorithm.equals("SLHDSA")) {
         throw new InvalidKeyException("SLH-DSA public key required, got: " + keyAlgorithm);
      }

      if (expectedVariant != null) {
         String normalizedKey = normalizeVariant(keyAlgorithm);
         String normalizedExpected = normalizeVariant(expectedVariant);
         if (!normalizedKey.equals(normalizedExpected)) {
            throw new InvalidKeyException("Key variant " + keyAlgorithm +
               " does not match expected variant " + expectedVariant);
         }
      }

      this.publicKeyEncoded = publicKey.getEncoded();
      if (this.publicKeyEncoded == null) {
         throw new InvalidKeyException("Public key encoding is null");
      }
   }

   private String normalizeVariant(String variant) {
      return variant.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
   }
}
