package net.glassless.provider.internal.lms;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * LMS (Leighton-Micali Signature) public key implementation.
 * LMS is a hash-based post-quantum signature scheme defined in RFC 8554 / NIST SP 800-208.
 * Only verification is supported (no signing or key generation).
 */
public class GlaSSLessLMSPublicKey implements PublicKey {

   private static final long serialVersionUID = 1L;

   private final byte[] encoded;

   public GlaSSLessLMSPublicKey(byte[] encoded) {
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return "LMS";
   }

   @Override
   public String getFormat() {
      return "X.509";
   }

   @Override
   public byte[] getEncoded() {
      return encoded.clone();
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof GlaSSLessLMSPublicKey other)) return false;
      return Arrays.equals(encoded, other.encoded);
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return "GlaSSLessLMSPublicKey [algorithm=LMS]";
   }
}
