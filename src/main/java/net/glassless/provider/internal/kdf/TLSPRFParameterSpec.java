package net.glassless.provider.internal.kdf;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Parameter specification for TLS Pseudo-Random Function (PRF).
 *
 * TLS PRF is used in TLS 1.0-1.2 for key derivation from the
 * master secret. TLS 1.2 uses SHA-256 by default.
 */
public class TLSPRFParameterSpec implements AlgorithmParameterSpec {

   private final byte[] secret;
   private final String label;
   private final byte[] seed;
   private final int keyLength;

   /**
    * Creates a TLSPRFParameterSpec.
    *
    * @param secret the secret (e.g., master secret or pre-master secret)
    * @param label the label string (e.g., "key expansion")
    * @param seed the seed (typically client_random + server_random)
    * @param keyLength the desired key length in bytes
    */
   public TLSPRFParameterSpec(byte[] secret, String label, byte[] seed, int keyLength) {
      if (secret == null || secret.length == 0) {
         throw new IllegalArgumentException("Secret cannot be null or empty");
      }
      if (label == null || label.isEmpty()) {
         throw new IllegalArgumentException("Label cannot be null or empty");
      }
      if (seed == null || seed.length == 0) {
         throw new IllegalArgumentException("Seed cannot be null or empty");
      }
      if (keyLength <= 0) {
         throw new IllegalArgumentException("Key length must be positive");
      }

      this.secret = secret.clone();
      this.label = label;
      this.seed = seed.clone();
      this.keyLength = keyLength;
   }

   public byte[] getSecret() {
      return secret.clone();
   }

   public String getLabel() {
      return label;
   }

   public byte[] getSeed() {
      return seed.clone();
   }

   public int getKeyLength() {
      return keyLength;
   }

   /**
    * Returns the combined label and seed as used by TLS-PRF.
    *
    * @return label bytes concatenated with seed
    */
   public byte[] getLabelAndSeed() {
      byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      byte[] combined = new byte[labelBytes.length + seed.length];
      System.arraycopy(labelBytes, 0, combined, 0, labelBytes.length);
      System.arraycopy(seed, 0, combined, labelBytes.length, seed.length);
      return combined;
   }

   /**
    * Clears sensitive data from memory.
    */
   public void clear() {
      Arrays.fill(secret, (byte) 0);
   }
}
