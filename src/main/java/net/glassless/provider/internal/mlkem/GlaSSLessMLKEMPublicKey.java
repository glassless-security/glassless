package net.glassless.provider.internal.mlkem;

import net.glassless.provider.internal.AbstractPublicKey;

/**
 * ML-KEM public key implementation.
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 variants.
 */
public class GlaSSLessMLKEMPublicKey extends AbstractPublicKey {

   private static final long serialVersionUID = 1L;

   public GlaSSLessMLKEMPublicKey(String algorithm, byte[] encoded) {
      super(algorithm, encoded);
   }
}
