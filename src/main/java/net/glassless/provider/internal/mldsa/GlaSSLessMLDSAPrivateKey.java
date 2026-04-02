package net.glassless.provider.internal.mldsa;

import java.io.Serial;

import net.glassless.provider.internal.AbstractPrivateKey;

/**
 * ML-DSA private key implementation with Destroyable support.
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 variants.
 */
public class GlaSSLessMLDSAPrivateKey extends AbstractPrivateKey {

   @Serial
   private static final long serialVersionUID = 1L;

   public GlaSSLessMLDSAPrivateKey(String algorithm, byte[] encoded) {
      super(algorithm, encoded);
   }
}
