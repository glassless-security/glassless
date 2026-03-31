package net.glassless.provider.internal.mlkem;

import net.glassless.provider.internal.AbstractPrivateKey;

/**
 * ML-KEM private key implementation with Destroyable support.
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 variants.
 */
public class GlaSSLessMLKEMPrivateKey extends AbstractPrivateKey {

   private static final long serialVersionUID = 1L;

   public GlaSSLessMLKEMPrivateKey(String algorithm, byte[] encoded) {
      super(algorithm, encoded);
   }
}
