package net.glassless.provider.internal;

import java.io.Serial;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.security.auth.Destroyable;

/**
 * Abstract base for PrivateKey implementations backed by encoded bytes.
 * Provides shared Destroyable support, equals/hashCode/getFormat/getEncoded.
 */
public abstract class AbstractPrivateKey implements PrivateKey, Destroyable {

   @Serial
   private static final long serialVersionUID = 1L;

   private final String algorithm;
   private final byte[] encoded;
   private boolean destroyed = false;

   protected AbstractPrivateKey(String algorithm, byte[] encoded) {
      this.algorithm = algorithm;
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return algorithm;
   }

   @Override
   public String getFormat() {
      return "PKCS#8";
   }

   @Override
   public byte[] getEncoded() {
      if (destroyed) {
         throw new IllegalStateException("Key has been destroyed");
      }
      return encoded.clone();
   }

   @Override
   public void destroy() {
      if (!destroyed) {
         Arrays.fill(encoded, (byte) 0);
         destroyed = true;
      }
   }

   @Override
   public boolean isDestroyed() {
      return destroyed;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof AbstractPrivateKey other)) return false;
      if (destroyed || other.destroyed) return false;
      return algorithm.equals(other.algorithm) && Arrays.equals(encoded, other.encoded);
   }

   @Override
   public int hashCode() {
      return destroyed ? 0 : Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return getClass().getSimpleName() + " [algorithm=" + algorithm + ", destroyed=" + destroyed + "]";
   }
}
