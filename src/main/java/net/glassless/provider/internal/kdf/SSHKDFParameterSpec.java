package net.glassless.provider.internal.kdf;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Parameter specification for SSH Key Derivation Function (RFC 4253).
 *
 * SSH uses this KDF to derive multiple keys from the shared secret
 * established during key exchange.
 */
public class SSHKDFParameterSpec implements AlgorithmParameterSpec {

   /** Initial IV client to server */
   public static final char TYPE_INITIAL_IV_CLI_TO_SRV = 'A';
   /** Initial IV server to client */
   public static final char TYPE_INITIAL_IV_SRV_TO_CLI = 'B';
   /** Encryption key client to server */
   public static final char TYPE_ENCRYPTION_KEY_CLI_TO_SRV = 'C';
   /** Encryption key server to client */
   public static final char TYPE_ENCRYPTION_KEY_SRV_TO_CLI = 'D';
   /** Integrity key client to server */
   public static final char TYPE_INTEGRITY_KEY_CLI_TO_SRV = 'E';
   /** Integrity key server to client */
   public static final char TYPE_INTEGRITY_KEY_SRV_TO_CLI = 'F';

   private final byte[] key;          // Shared secret K
   private final byte[] xcghash;      // Exchange hash H
   private final byte[] sessionId;    // Session identifier
   private final char type;           // Key type (A-F)
   private final int keyLength;

   /**
    * Creates an SSHKDFParameterSpec.
    *
    * @param key the shared secret K from key exchange
    * @param xcghash the exchange hash H
    * @param sessionId the session identifier
    * @param type the key type character (A-F)
    * @param keyLength the desired key length in bytes
    */
   public SSHKDFParameterSpec(byte[] key, byte[] xcghash, byte[] sessionId, char type, int keyLength) {
      if (key == null || key.length == 0) {
         throw new IllegalArgumentException("Key cannot be null or empty");
      }
      if (xcghash == null || xcghash.length == 0) {
         throw new IllegalArgumentException("Exchange hash cannot be null or empty");
      }
      if (sessionId == null || sessionId.length == 0) {
         throw new IllegalArgumentException("Session ID cannot be null or empty");
      }
      if (type < 'A' || type > 'F') {
         throw new IllegalArgumentException("Type must be A-F");
      }
      if (keyLength <= 0) {
         throw new IllegalArgumentException("Key length must be positive");
      }

      this.key = key.clone();
      this.xcghash = xcghash.clone();
      this.sessionId = sessionId.clone();
      this.type = type;
      this.keyLength = keyLength;
   }

   public byte[] getKey() {
      return key.clone();
   }

   public byte[] getXcghash() {
      return xcghash.clone();
   }

   public byte[] getSessionId() {
      return sessionId.clone();
   }

   public char getType() {
      return type;
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
