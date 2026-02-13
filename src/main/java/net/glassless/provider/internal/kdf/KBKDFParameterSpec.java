package net.glassless.provider.internal.kdf;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Parameter specification for Key-Based Key Derivation Function (SP 800-108).
 *
 * KBKDF is a NIST-approved KDF that derives keys from an existing key
 * using a pseudorandom function (typically HMAC or CMAC).
 */
public class KBKDFParameterSpec implements AlgorithmParameterSpec {

   /** Counter mode (most common) */
   public static final String MODE_COUNTER = "counter";
   /** Feedback mode */
   public static final String MODE_FEEDBACK = "feedback";
   /** Double-pipeline mode */
   public static final String MODE_PIPELINE = "pipeline";

   private final byte[] key;
   private final byte[] label;
   private final byte[] context;
   private final String mode;
   private final int keyLength;

   /**
    * Creates a KBKDFParameterSpec.
    *
    * @param key the input key (Ki)
    * @param label the label (optional, can be null)
    * @param context the context (optional, can be null)
    * @param mode the KDF mode (counter, feedback, or pipeline)
    * @param keyLength the desired key length in bytes
    */
   public KBKDFParameterSpec(byte[] key, byte[] label, byte[] context, String mode, int keyLength) {
      if (key == null || key.length == 0) {
         throw new IllegalArgumentException("Key cannot be null or empty");
      }
      if (mode == null || (!mode.equals(MODE_COUNTER) && !mode.equals(MODE_FEEDBACK) && !mode.equals(MODE_PIPELINE))) {
         throw new IllegalArgumentException("Mode must be 'counter', 'feedback', or 'pipeline'");
      }
      if (keyLength <= 0) {
         throw new IllegalArgumentException("Key length must be positive");
      }

      this.key = key.clone();
      this.label = label != null ? label.clone() : null;
      this.context = context != null ? context.clone() : null;
      this.mode = mode;
      this.keyLength = keyLength;
   }

   /**
    * Creates a KBKDFParameterSpec with counter mode (default).
    *
    * @param key the input key
    * @param label the label
    * @param context the context
    * @param keyLength the desired key length in bytes
    */
   public KBKDFParameterSpec(byte[] key, byte[] label, byte[] context, int keyLength) {
      this(key, label, context, MODE_COUNTER, keyLength);
   }

   public byte[] getKey() {
      return key.clone();
   }

   public byte[] getLabel() {
      return label != null ? label.clone() : null;
   }

   public byte[] getContext() {
      return context != null ? context.clone() : null;
   }

   public String getMode() {
      return mode;
   }

   public int getKeyLength() {
      return keyLength;
   }

   /**
    * Clears sensitive data from memory.
    */
   public void clear() {
      Arrays.fill(key, (byte) 0);
   }
}
