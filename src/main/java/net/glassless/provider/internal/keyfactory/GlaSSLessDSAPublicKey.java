package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.util.Arrays;

/**
 * DSA public key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessDSAPublicKey implements DSAPublicKey {

   @Serial
   private static final long serialVersionUID = 1L;

   private final BigInteger y;
   private final DSAParameterSpec params;
   private final byte[] encoded;

   public GlaSSLessDSAPublicKey(BigInteger y, DSAParameterSpec params, byte[] encoded) {
      this.y = y;
      this.params = params;
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return "DSA";
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
   public BigInteger getY() {
      return y;
   }

   @Override
   public DSAParams getParams() {
      return params;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof DSAPublicKey other)) return false;
      return y.equals(other.getY()) && Arrays.equals(encoded, other.getEncoded());
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return "GlaSSLessDSAPublicKey [p bitLength=" + params.getP().bitLength() + "]";
   }
}
