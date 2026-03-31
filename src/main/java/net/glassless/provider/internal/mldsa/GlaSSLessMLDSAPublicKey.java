package net.glassless.provider.internal.mldsa;

import net.glassless.provider.internal.AbstractPublicKey;

/**
 * ML-DSA public key implementation.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 variants.
 */
public class GlaSSLessMLDSAPublicKey extends AbstractPublicKey {

   private static final long serialVersionUID = 1L;

   public GlaSSLessMLDSAPublicKey(String algorithm, byte[] encoded) {
      super(algorithm, encoded);
   }
}
