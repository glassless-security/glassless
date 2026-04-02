package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.Destroyable;

/**
 * DH private key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessDHPrivateKey implements DHPrivateKey, Destroyable {

   @Serial
   private static final long serialVersionUID = 1L;

   private boolean destroyed = false;

   private final BigInteger x;
   private final DHParameterSpec params;
   private final byte[] encoded;

   public GlaSSLessDHPrivateKey(BigInteger x, DHParameterSpec params, byte[] encoded) {
      this.x = x;
      this.params = params;
      this.encoded = encoded != null ? encoded.clone() : null;
   }

   @Override
   public String getAlgorithm() {
      return "DH";
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
   public DHParameterSpec getParams() {
      return params;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof DHPrivateKey other)) return false;
      return x.equals(other.getX());
   }

   @Override
   public int hashCode() {
      return x.hashCode();
   }

   @Override
   public String toString() {
      return "GlaSSLessDHPrivateKey [p bitLength=" + params.getP().bitLength() + "]";
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
