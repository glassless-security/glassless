package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;
import java.util.Arrays;

import javax.security.auth.Destroyable;

/**
 * DSA private key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessDSAPrivateKey implements DSAPrivateKey, Destroyable {

   @Serial
   private static final long serialVersionUID = 1L;

   private boolean destroyed = false;

   private final BigInteger x;
   private final DSAParameterSpec params;
   private final byte[] encoded;

   public GlaSSLessDSAPrivateKey(BigInteger x, DSAParameterSpec params, byte[] encoded) {
      this.x = x;
      this.params = params;
      this.encoded = encoded != null ? encoded.clone() : null;
   }

   @Override
   public String getAlgorithm() {
      return "DSA";
   }

   @Override
   public String getFormat() {
      checkDestroyed();
      return encoded != null ? "PKCS#8" : null;
   }

   @Override
   public byte[] getEncoded() {
      checkDestroyed();
      return encoded != null ? encoded.clone() : null;
   }

   @Override
   public BigInteger getX() {
      return x;
   }

   @Override
   public DSAParams getParams() {
      return params;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof DSAPrivateKey other)) return false;
      return x.equals(other.getX());
   }

   @Override
   public int hashCode() {
      return x.hashCode();
   }

   @Override
   public String toString() {
      return "GlaSSLessDSAPrivateKey [p bitLength=" + params.getP().bitLength() + "]";
   }

   @Override
   public void destroy() {
      if (!destroyed) {
         if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
         }
         destroyed = true;
      }
   }

   @Override
   public boolean isDestroyed() {
      return destroyed;
   }

   private void checkDestroyed() {
      if (destroyed) {
         throw new IllegalStateException("Key has been destroyed");
      }
   }
}
