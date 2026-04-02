package net.glassless.provider.internal;

import java.io.Serial;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Abstract base for PublicKey implementations backed by encoded bytes.
 * Provides shared equals/hashCode/getFormat/getEncoded implementations.
 */
public abstract class AbstractPublicKey implements PublicKey {

   @Serial
   private static final long serialVersionUID = 1L;

   private final String algorithm;
   private final byte[] encoded;

   protected AbstractPublicKey(String algorithm, byte[] encoded) {
      this.algorithm = algorithm;
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return algorithm;
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
      if (!(obj instanceof AbstractPublicKey other)) return false;
      return algorithm.equals(other.algorithm) && Arrays.equals(encoded, other.encoded);
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return getClass().getSimpleName() + " [algorithm=" + algorithm + "]";
   }
}
