package net.glassless.provider.internal.kdf;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Parameter specification for TLS 1.3 Key Derivation Function (HKDF-based).
 *
 * TLS 1.3 uses HKDF for key derivation with two modes:
 * <ul>
 *   <li>EXTRACT_ONLY: Performs HKDF-Extract to derive the PRK from input key material</li>
 *   <li>EXPAND_ONLY: Performs HKDF-Expand-Label to derive keys from PRK</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8446#section-7.1">RFC 8446 Section 7.1</a>
 */
public class TLS13KDFParameterSpec implements AlgorithmParameterSpec {

   /**
    * HKDF-Extract mode: derives PRK from input key material and salt.
    */
   public static final int MODE_EXTRACT_ONLY = 1;

   /**
    * HKDF-Expand-Label mode: derives key material from PRK with label and context.
    */
   public static final int MODE_EXPAND_ONLY = 2;

   /**
    * Default TLS 1.3 prefix as specified in RFC 8446.
    */
   public static final byte[] TLS13_PREFIX = "tls13 ".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

   private final int mode;
   private final byte[] key;
   private final byte[] salt;
   private final byte[] prefix;
   private final byte[] label;
   private final byte[] data;
   private final int keyLength;

   private TLS13KDFParameterSpec(Builder builder) {
      this.mode = builder.mode;
      this.key = builder.key != null ? builder.key.clone() : null;
      this.salt = builder.salt != null ? builder.salt.clone() : null;
      this.prefix = builder.prefix != null ? builder.prefix.clone() : TLS13_PREFIX.clone();
      this.label = builder.label != null ? builder.label.clone() : null;
      this.data = builder.data != null ? builder.data.clone() : null;
      this.keyLength = builder.keyLength;
   }

   /**
    * Returns the mode (EXTRACT_ONLY or EXPAND_ONLY).
    */
   public int getMode() {
      return mode;
   }

   /**
    * Returns the mode as an OpenSSL string.
    */
   public String getModeString() {
      return mode == MODE_EXTRACT_ONLY ? "EXTRACT_ONLY" : "EXPAND_ONLY";
   }

   /**
    * Returns the input key material (for extract) or PRK (for expand).
    */
   public byte[] getKey() {
      return key != null ? key.clone() : null;
   }

   /**
    * Returns the salt (for extract mode).
    */
   public byte[] getSalt() {
      return salt != null ? salt.clone() : null;
   }

   /**
    * Returns the prefix (default: "tls13 ").
    */
   public byte[] getPrefix() {
      return prefix != null ? prefix.clone() : null;
   }

   /**
    * Returns the label (for expand mode).
    */
   public byte[] getLabel() {
      return label != null ? label.clone() : null;
   }

   /**
    * Returns the context data (for expand mode).
    */
   public byte[] getData() {
      return data != null ? data.clone() : null;
   }

   /**
    * Returns the desired output key length in bytes.
    */
   public int getKeyLength() {
      return keyLength;
   }

   /**
    * Clears sensitive data from memory.
    */
   public void clear() {
      if (key != null) Arrays.fill(key, (byte) 0);
      if (salt != null) Arrays.fill(salt, (byte) 0);
   }

   /**
    * Creates a builder for extract mode.
    *
    * @param inputKeyMaterial the input key material
    * @param salt the salt (can be null for zero-length salt)
    * @param keyLength the PRK length (must match hash output size)
    * @return a builder configured for extract mode
    */
   public static Builder forExtract(byte[] inputKeyMaterial, byte[] salt, int keyLength) {
      return new Builder()
         .mode(MODE_EXTRACT_ONLY)
         .key(inputKeyMaterial)
         .salt(salt)
         .keyLength(keyLength);
   }

   /**
    * Creates a builder for expand mode (HKDF-Expand-Label).
    *
    * @param prk the pseudo-random key from extract
    * @param label the label (e.g., "key", "iv", "finished")
    * @param context the context data (can be empty)
    * @param keyLength the desired output length
    * @return a builder configured for expand mode
    */
   public static Builder forExpand(byte[] prk, String label, byte[] context, int keyLength) {
      return new Builder()
         .mode(MODE_EXPAND_ONLY)
         .key(prk)
         .label(label.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
         .data(context)
         .keyLength(keyLength);
   }

   /**
    * Builder for TLS13KDFParameterSpec.
    */
   public static class Builder {
      private int mode;
      private byte[] key;
      private byte[] salt;
      private byte[] prefix;
      private byte[] label;
      private byte[] data;
      private int keyLength;

      /**
       * Sets the mode (EXTRACT_ONLY or EXPAND_ONLY).
       */
      public Builder mode(int mode) {
         if (mode != MODE_EXTRACT_ONLY && mode != MODE_EXPAND_ONLY) {
            throw new IllegalArgumentException("Mode must be MODE_EXTRACT_ONLY or MODE_EXPAND_ONLY");
         }
         this.mode = mode;
         return this;
      }

      /**
       * Sets the input key material (for extract) or PRK (for expand).
       */
      public Builder key(byte[] key) {
         this.key = key;
         return this;
      }

      /**
       * Sets the salt for extract mode.
       */
      public Builder salt(byte[] salt) {
         this.salt = salt;
         return this;
      }

      /**
       * Sets the prefix (default: "tls13 ").
       */
      public Builder prefix(byte[] prefix) {
         this.prefix = prefix;
         return this;
      }

      /**
       * Sets the label for expand mode.
       */
      public Builder label(byte[] label) {
         this.label = label;
         return this;
      }

      /**
       * Sets the context data for expand mode.
       */
      public Builder data(byte[] data) {
         this.data = data;
         return this;
      }

      /**
       * Sets the desired output key length.
       */
      public Builder keyLength(int keyLength) {
         if (keyLength <= 0) {
            throw new IllegalArgumentException("Key length must be positive");
         }
         this.keyLength = keyLength;
         return this;
      }

      /**
       * Builds the parameter specification.
       */
      public TLS13KDFParameterSpec build() {
         if (key == null || key.length == 0) {
            throw new IllegalStateException("Key is required");
         }
         if (keyLength <= 0) {
            throw new IllegalStateException("Key length must be positive");
         }
         if (mode == MODE_EXPAND_ONLY && (label == null || label.length == 0)) {
            throw new IllegalStateException("Label is required for expand mode");
         }
         return new TLS13KDFParameterSpec(this);
      }
   }
}
