package net.glassless.provider.internal.slhdsa;

import net.glassless.provider.internal.AbstractPrivateKey;

/**
 * SLH-DSA private key implementation with Destroyable support.
 * Supports all 12 SLH-DSA variants (SHA2/SHAKE x 128/192/256 x s/f).
 */
public class GlaSSLessSLHDSAPrivateKey extends AbstractPrivateKey {

   private static final long serialVersionUID = 1L;

   public GlaSSLessSLHDSAPrivateKey(String algorithm, byte[] encoded) {
      super(algorithm, encoded);
   }
}
