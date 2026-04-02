package net.glassless.provider.internal.lms;

import java.io.Serial;

import net.glassless.provider.internal.AbstractPublicKey;

/**
 * LMS (Leighton-Micali Signature) public key implementation.
 * LMS is a hash-based post-quantum signature scheme defined in RFC 8554 / NIST SP 800-208.
 * Only verification is supported (no signing or key generation).
 */
public class GlaSSLessLMSPublicKey extends AbstractPublicKey {

   @Serial
   private static final long serialVersionUID = 1L;

   public GlaSSLessLMSPublicKey(byte[] encoded) {
      super("LMS", encoded);
   }
}
