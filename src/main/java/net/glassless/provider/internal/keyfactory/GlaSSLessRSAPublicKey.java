package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * RSA public key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessRSAPublicKey implements RSAPublicKey {

   @Serial
   private static final long serialVersionUID = 1L;

   private final BigInteger modulus;
   private final BigInteger publicExponent;
   private final byte[] encoded;

   public GlaSSLessRSAPublicKey(BigInteger modulus, BigInteger publicExponent, byte[] encoded) {
      this.modulus = modulus;
      this.publicExponent = publicExponent;
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return "RSA";
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
   public BigInteger getModulus() {
      return modulus;
   }

   @Override
   public BigInteger getPublicExponent() {
      return publicExponent;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof RSAPublicKey other)) return false;
      return modulus.equals(other.getModulus())
         && publicExponent.equals(other.getPublicExponent());
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return "GlaSSLessRSAPublicKey [modulus bitLength=" + modulus.bitLength() + "]";
   }
}
