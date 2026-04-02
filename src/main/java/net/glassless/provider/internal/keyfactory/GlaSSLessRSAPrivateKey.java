package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;

import javax.security.auth.Destroyable;

/**
 * RSA private key implementation backed by OpenSSL-derived parameters.
 * Implements RSAPrivateCrtKey to provide CRT parameters when available.
 */
public class GlaSSLessRSAPrivateKey implements RSAPrivateCrtKey, Destroyable {

   @Serial
   private static final long serialVersionUID = 1L;

   private boolean destroyed = false;

   private final BigInteger modulus;
   private final BigInteger publicExponent;
   private final BigInteger privateExponent;
   private final BigInteger primeP;
   private final BigInteger primeQ;
   private final BigInteger primeExponentP;
   private final BigInteger primeExponentQ;
   private final BigInteger crtCoefficient;
   private final byte[] encoded;

   public GlaSSLessRSAPrivateKey(
         BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent,
         BigInteger primeP, BigInteger primeQ,
         BigInteger primeExponentP, BigInteger primeExponentQ,
         BigInteger crtCoefficient, byte[] encoded) {
      this.modulus = modulus;
      this.publicExponent = publicExponent;
      this.privateExponent = privateExponent;
      this.primeP = primeP;
      this.primeQ = primeQ;
      this.primeExponentP = primeExponentP;
      this.primeExponentQ = primeExponentQ;
      this.crtCoefficient = crtCoefficient;
      this.encoded = encoded != null ? encoded.clone() : null;
   }

   @Override
   public String getAlgorithm() {
      return "RSA";
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
   public BigInteger getModulus() {
      return modulus;
   }

   @Override
   public BigInteger getPublicExponent() {
      return publicExponent;
   }

   @Override
   public BigInteger getPrivateExponent() {
      return privateExponent;
   }

   @Override
   public BigInteger getPrimeP() {
      return primeP;
   }

   @Override
   public BigInteger getPrimeQ() {
      return primeQ;
   }

   @Override
   public BigInteger getPrimeExponentP() {
      return primeExponentP;
   }

   @Override
   public BigInteger getPrimeExponentQ() {
      return primeExponentQ;
   }

   @Override
   public BigInteger getCrtCoefficient() {
      return crtCoefficient;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof RSAPrivateCrtKey other)) return false;
      return modulus.equals(other.getModulus())
         && privateExponent.equals(other.getPrivateExponent());
   }

   @Override
   public int hashCode() {
      return modulus.hashCode() ^ privateExponent.hashCode();
   }

   @Override
   public String toString() {
      return "GlaSSLessRSAPrivateKey [modulus bitLength=" + modulus.bitLength() + "]";
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
