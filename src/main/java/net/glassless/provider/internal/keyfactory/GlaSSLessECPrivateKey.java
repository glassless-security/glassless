package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

/**
 * EC private key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessECPrivateKey implements ECPrivateKey {

   @Serial
   private static final long serialVersionUID = 1L;

   private final BigInteger s;
   private final ECParameterSpec params;
   private final byte[] encoded;

   public GlaSSLessECPrivateKey(BigInteger s, ECParameterSpec params, byte[] encoded) {
      this.s = s;
      this.params = params;
      this.encoded = encoded != null ? encoded.clone() : null;
   }

   @Override
   public String getAlgorithm() {
      return "EC";
   }

   @Override
   public String getFormat() {
      return encoded != null ? "PKCS#8" : null;
   }

   @Override
   public byte[] getEncoded() {
      return encoded != null ? encoded.clone() : null;
   }

   @Override
   public BigInteger getS() {
      return s;
   }

   @Override
   public ECParameterSpec getParams() {
      return params;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof ECPrivateKey other)) return false;
      return s.equals(other.getS());
   }

   @Override
   public int hashCode() {
      return s.hashCode();
   }

   @Override
   public String toString() {
      return "GlaSSLessECPrivateKey [fieldSize=" + params.getCurve().getField().getFieldSize() + "]";
   }

   /**
    * Clears the private key material from memory.
    */
   public void destroy() {
      if (encoded != null) {
         Arrays.fill(encoded, (byte) 0);
      }
   }
}
