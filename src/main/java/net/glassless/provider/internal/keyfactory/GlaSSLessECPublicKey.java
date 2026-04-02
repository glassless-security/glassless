package net.glassless.provider.internal.keyfactory;

import java.io.Serial;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * EC public key implementation backed by OpenSSL-derived parameters.
 */
public class GlaSSLessECPublicKey implements ECPublicKey {

   @Serial
   private static final long serialVersionUID = 1L;

   private final ECPoint w;
   private final ECParameterSpec params;
   private final byte[] encoded;

   public GlaSSLessECPublicKey(ECPoint w, ECParameterSpec params, byte[] encoded) {
      this.w = w;
      this.params = params;
      this.encoded = encoded.clone();
   }

   @Override
   public String getAlgorithm() {
      return "EC";
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
   public ECPoint getW() {
      return w;
   }

   @Override
   public ECParameterSpec getParams() {
      return params;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof ECPublicKey other)) return false;
      return w.equals(other.getW()) && Arrays.equals(encoded, other.getEncoded());
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(encoded);
   }

   @Override
   public String toString() {
      return "GlaSSLessECPublicKey [fieldSize=" + params.getCurve().getField().getFieldSize() + "]";
   }
}
