package net.glassless.provider.internal;

import java.lang.System.Logger;

/**
 * Centralized logging for the GlaSSLess provider.
 *
 * <p>Uses {@link System.Logger} (Platform Logging API), which routes to
 * {@code java.util.logging} by default or to any SPI-configured backend
 * (SLF4J, Log4j, etc.).
 *
 * <p>Logging is at two levels:
 * <ul>
 *   <li>{@code DEBUG} — initialization and completion of crypto operations
 *       (cipher init, sign, verify, key generation, etc.)
 *   <li>{@code TRACE} — data-flow details (update calls with byte counts)
 * </ul>
 *
 * <h2>Activation</h2>
 * <p>With default JUL backend, create a {@code logging.properties} file:
 * <pre>
 * handlers = java.util.logging.ConsoleHandler
 * java.util.logging.ConsoleHandler.level = ALL
 *
 * # Enable all GlaSSLess logging
 * net.glassless.provider.level = FINE
 *
 * # Or enable specific categories
 * net.glassless.provider.cipher.level = FINE
 * net.glassless.provider.digest.level = FINE
 * net.glassless.provider.signature.level = FINE
 * </pre>
 * Then run with: {@code java -Djava.util.logging.config.file=logging.properties ...}
 */
public final class GlaSSLessLog {

   // One logger per JCA service type, matching the package hierarchy
   public static final Logger CIPHER = System.getLogger("net.glassless.provider.cipher");
   public static final Logger DIGEST = System.getLogger("net.glassless.provider.digest");
   public static final Logger SIGNATURE = System.getLogger("net.glassless.provider.signature");
   public static final Logger MAC = System.getLogger("net.glassless.provider.mac");
   public static final Logger KEY_AGREEMENT = System.getLogger("net.glassless.provider.keyagreement");
   public static final Logger KEY_PAIR_GEN = System.getLogger("net.glassless.provider.keypairgen");
   public static final Logger KEY_GEN = System.getLogger("net.glassless.provider.keygen");
   public static final Logger KEY_FACTORY = System.getLogger("net.glassless.provider.keyfactory");
   public static final Logger SECURE_RANDOM = System.getLogger("net.glassless.provider.securerandom");
   public static final Logger KDF = System.getLogger("net.glassless.provider.kdf");
   public static final Logger KEM = System.getLogger("net.glassless.provider.kem");

   private GlaSSLessLog() {
   }

   /** Maps Cipher opmode int to a readable string. */
   public static String opmodeName(int opmode) {
      return switch (opmode) {
         case 1 -> "ENCRYPT";
         case 2 -> "DECRYPT";
         case 3 -> "WRAP";
         case 4 -> "UNWRAP";
         default -> "UNKNOWN(" + opmode + ")";
      };
   }

   /** Formats a key size from encoded key bytes, returning bits. */
   public static int keySizeBits(byte[] encoded) {
      return encoded != null ? encoded.length * 8 : 0;
   }
}
