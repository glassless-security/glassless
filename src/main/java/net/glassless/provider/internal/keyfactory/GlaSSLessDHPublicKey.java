package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * DH public key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessDHPublicKey implements DHPublicKey {

   @Serial
   private static final long serialVersionUID = 1L;

   private final BigInteger y;
   private final DHParameterSpec params;
   private final byte[] encoded;

   public GlaSSLessDHPublicKey(BigInteger y, DHParameterSpec params, byte[] encoded) {
      this.y = y;
      this.params = params;
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return "DH";
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
   public DHParameterSpec getParams() {
      return params;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof DHPublicKey other)) return false;
      return y.equals(other.getY()) && Arrays.equals(encoded, other.getEncoded());
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return "GlaSSLessDHPublicKey [p bitLength=" + params.getP().bitLength() + "]";
   }
}
