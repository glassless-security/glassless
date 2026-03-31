package net.glassless.provider.internal.lms;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import net.glassless.provider.internal.AbstractSingleShotSignature;

/**
 * LMS (Leighton-Micali Signature) verification implementation using OpenSSL.
 * LMS is a stateful hash-based signature scheme (RFC 8554 / NIST SP 800-208).
 *
 * <p>This implementation is <b>verification-only</b>. Signing and key generation
 * are not supported because LMS is a stateful scheme where each private key
 * can only sign a limited number of messages, and state management must be
 * handled by the key owner.
 *
 * <p>LMS uses single-shot verification (EVP_DigestVerify) similar to SLH-DSA.
 */
public class LMSSignature extends AbstractSingleShotSignature {

   public LMSSignature() {
      super("LMS");
   }

   @Override
   protected void validateAndInitSign(PrivateKey privateKey) throws InvalidKeyException {
      throw new InvalidKeyException("LMS signing is not supported. " +
         "LMS is a stateful signature scheme; only verification is available.");
   }

   @Override
   protected void validateAndInitVerify(PublicKey publicKey) throws InvalidKeyException {
      if (publicKey == null) {
         throw new InvalidKeyException("Public key cannot be null");
      }

      String keyAlgorithm = publicKey.getAlgorithm();
      if (!"LMS".equalsIgnoreCase(keyAlgorithm) && !"HSS".equalsIgnoreCase(keyAlgorithm)) {
         throw new InvalidKeyException("LMS public key required, got: " + keyAlgorithm);
      }

      this.publicKeyEncoded = publicKey.getEncoded();
      if (this.publicKeyEncoded == null) {
         throw new InvalidKeyException("Public key encoding is null");
      }
   }

   @Override
   protected byte[] engineSign() throws SignatureException {
      throw new SignatureException("LMS signing is not supported. " +
         "LMS is a stateful signature scheme; only verification is available.");
   }
}
