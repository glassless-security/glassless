package net.glassless.provider.internal.slhdsa;

import net.glassless.provider.internal.AbstractPublicKey;

/**
 * SLH-DSA public key implementation.
 * Supports all 12 SLH-DSA variants (SHA2/SHAKE x 128/192/256 x s/f).
 */
public class GlaSSLessSLHDSAPublicKey extends AbstractPublicKey {

   private static final long serialVersionUID = 1L;

   public GlaSSLessSLHDSAPublicKey(String algorithm, byte[] encoded) {
      super(algorithm, encoded);
   }
}
