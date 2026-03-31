package net.glassless.provider.internal.eddsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

import net.glassless.provider.internal.AbstractSingleShotSignature;

/**
 * EdDSA Signature implementation using OpenSSL.
 * Supports Ed25519 and Ed448.
 * <p>
 * EdDSA requires single-shot signing (EVP_DigestSign/EVP_DigestVerify)
 * rather than the update/final pattern used by other algorithms.
 */
public class EdDSASignature extends AbstractSingleShotSignature {

   private final String expectedCurve;  // null means accept any EdDSA curve

   public EdDSASignature() {
      this(null);
   }

   protected EdDSASignature(String expectedCurve) {
      super("EdDSA");
      this.expectedCurve = expectedCurve;
   }

   @Override
   protected void validateAndInitSign(PrivateKey privateKey) throws InvalidKeyException {
      if (!(privateKey instanceof EdECPrivateKey edKey)) {
         throw new InvalidKeyException("EdECPrivateKey required, got: " +
            (privateKey == null ? "null" : privateKey.getClass().getName()));
      }

      validateCurve(edKey.getParams().getName());

      this.privateKeyEncoded = privateKey.getEncoded();
      if (this.privateKeyEncoded == null) {
         throw new InvalidKeyException("Private key encoding is null");
      }
   }

   @Override
   protected void validateAndInitVerify(PublicKey publicKey) throws InvalidKeyException {
      if (!(publicKey instanceof EdECPublicKey edKey)) {
         throw new InvalidKeyException("EdECPublicKey required, got: " +
            (publicKey == null ? "null" : publicKey.getClass().getName()));
      }

      validateCurve(edKey.getParams().getName());

      this.publicKeyEncoded = publicKey.getEncoded();
      if (this.publicKeyEncoded == null) {
         throw new InvalidKeyException("Public key encoding is null");
      }
   }

   private void validateCurve(String curveName) throws InvalidKeyException {
      if (expectedCurve != null && !expectedCurve.equalsIgnoreCase(curveName)) {
         throw new InvalidKeyException("Key curve " + curveName +
            " does not match expected curve " + expectedCurve);
      }
      if (!curveName.equalsIgnoreCase("Ed25519") && !curveName.equalsIgnoreCase("Ed448")) {
         throw new InvalidKeyException("Unsupported EdDSA curve: " + curveName);
      }
   }
}
