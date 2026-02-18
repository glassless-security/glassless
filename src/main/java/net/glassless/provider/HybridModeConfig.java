package net.glassless.provider;

import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Configuration for hybrid mode operation.
 *
 * <p>Hybrid mode allows GlaSSLess to delegate certain algorithms to the default
 * JDK provider for better performance. This is useful because JDK's HotSpot
 * intrinsics outperform OpenSSL via FFM for certain operations:
 * <ul>
 *   <li>SHA-256/SHA-512 (small data &lt;1KB): JDK is ~4-6x faster</li>
 *   <li>HMAC-SHA256/SHA512 (small data &lt;1KB): JDK is ~4-8x faster</li>
 *   <li>SecureRandom (small buffers &lt;64B): JDK is ~2x faster</li>
 *   <li>ML-KEM operations: JDK is ~1.7-2.5x faster</li>
 * </ul>
 *
 * <p>Configuration is done via Java Security properties:
 * <pre>
 * # Enable hybrid mode
 * glassless.hybrid.enabled=true
 *
 * # Per-service-type algorithm lists (optional overrides)
 * glassless.hybrid.delegate.MessageDigest=SHA-256,SHA-512
 * glassless.hybrid.delegate.Mac=HmacSHA256,HmacSHA512
 * glassless.hybrid.delegate.SecureRandom=NativePRNG,DRBG
 * glassless.hybrid.delegate.KEM=ML-KEM-512,ML-KEM-768,ML-KEM-1024
 * </pre>
 *
 * <p><strong>Important:</strong> Hybrid mode is automatically disabled when FIPS mode
 * is active, since FIPS compliance requires using the FIPS-validated OpenSSL
 * implementation for all cryptographic operations.
 */
public final class HybridModeConfig {

   private static final String HYBRID_ENABLED_PROPERTY = "glassless.hybrid.enabled";
   private static final String HYBRID_DELEGATE_PREFIX = "glassless.hybrid.delegate.";

   // Default algorithms to delegate in hybrid mode (based on benchmark results)
   private static final Map<String, Set<String>> DEFAULT_DELEGATED_ALGORITHMS;

   static {
      Map<String, Set<String>> defaults = new HashMap<>();

      // MessageDigest: SHA-256, SHA-512 are ~4-6x faster in JDK for small data
      defaults.put("MessageDigest", Set.of("SHA-256", "SHA-512"));

      // Mac: HMAC-SHA256, HMAC-SHA512 are ~4-8x faster in JDK for small data
      defaults.put("Mac", Set.of("HmacSHA256", "HmacSHA512"));

      // SecureRandom: NativePRNG, DRBG are ~2x faster in JDK for small buffers
      defaults.put("SecureRandom", Set.of("NativePRNG", "DRBG"));

      // KEM: ML-KEM operations are ~1.7-2.5x faster in JDK
      defaults.put("KEM", Set.of("ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"));

      // KeyPairGenerator: ML-KEM key generation is ~2x faster in JDK
      defaults.put("KeyPairGenerator", Set.of("ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"));

      DEFAULT_DELEGATED_ALGORITHMS = Collections.unmodifiableMap(defaults);
   }

   // Cached values
   private static volatile Boolean cachedHybridEnabled = null;
   private static volatile Map<String, Set<String>> cachedDelegatedAlgorithms = null;

   private HybridModeConfig() {
      // Utility class
   }

   /**
    * Returns whether hybrid mode is enabled.
    *
    * <p>This method checks:
    * <ol>
    *   <li>System property {@code glassless.hybrid.enabled}</li>
    *   <li>Security property {@code glassless.hybrid.enabled}</li>
    * </ol>
    *
    * <p>The result is cached after the first call for performance.
    *
    * @return true if hybrid mode is enabled, false otherwise
    */
   public static boolean isHybridEnabled() {
      if (cachedHybridEnabled != null) {
         return cachedHybridEnabled;
      }

      synchronized (HybridModeConfig.class) {
         if (cachedHybridEnabled != null) {
            return cachedHybridEnabled;
         }

         cachedHybridEnabled = detectHybridEnabled();
         return cachedHybridEnabled;
      }
   }

   /**
    * Detects whether hybrid mode is enabled through various mechanisms.
    */
   private static boolean detectHybridEnabled() {
      // 1. Check Java system property first (allows override)
      String propertyValue = System.getProperty(HYBRID_ENABLED_PROPERTY);
      if (propertyValue != null) {
         if ("true".equalsIgnoreCase(propertyValue)) {
            return true;
         } else if ("false".equalsIgnoreCase(propertyValue)) {
            return false;
         }
         // Invalid value, continue with other checks
      }

      // 2. Check Security property
      String securityValue = Security.getProperty(HYBRID_ENABLED_PROPERTY);
      if (securityValue != null) {
         return "true".equalsIgnoreCase(securityValue);
      }

      // Default: disabled
      return false;
   }

   /**
    * Returns whether the specified algorithm should be delegated to the JDK provider.
    *
    * @param serviceType the JCA service type (e.g., "MessageDigest", "Mac")
    * @param algorithm the algorithm name (e.g., "SHA-256", "HmacSHA256")
    * @return true if the algorithm should be delegated, false otherwise
    */
   public static boolean shouldDelegate(String serviceType, String algorithm) {
      Set<String> delegated = getDelegatedAlgorithms(serviceType);
      if (delegated.isEmpty()) {
         return false;
      }

      // Check exact match
      if (delegated.contains(algorithm)) {
         return true;
      }

      // Check aliases (case-insensitive for common variations)
      String normalizedAlgorithm = normalizeAlgorithmName(algorithm);
      for (String delegatedAlgo : delegated) {
         if (normalizeAlgorithmName(delegatedAlgo).equals(normalizedAlgorithm)) {
            return true;
         }
      }

      return false;
   }

   /**
    * Normalizes algorithm names for comparison.
    */
   private static String normalizeAlgorithmName(String algorithm) {
      // Handle common variations: SHA256 vs SHA-256, etc.
      return algorithm.replace("-", "").toUpperCase();
   }

   /**
    * Returns the set of algorithms to delegate for the specified service type.
    *
    * @param serviceType the JCA service type (e.g., "MessageDigest", "Mac")
    * @return set of algorithm names to delegate (may be empty, never null)
    */
   public static Set<String> getDelegatedAlgorithms(String serviceType) {
      Map<String, Set<String>> allDelegated = getAllDelegatedAlgorithms();
      return allDelegated.getOrDefault(serviceType, Collections.emptySet());
   }

   /**
    * Returns all delegated algorithms by service type.
    */
   private static Map<String, Set<String>> getAllDelegatedAlgorithms() {
      if (cachedDelegatedAlgorithms != null) {
         return cachedDelegatedAlgorithms;
      }

      synchronized (HybridModeConfig.class) {
         if (cachedDelegatedAlgorithms != null) {
            return cachedDelegatedAlgorithms;
         }

         cachedDelegatedAlgorithms = loadDelegatedAlgorithms();
         return cachedDelegatedAlgorithms;
      }
   }

   /**
    * Loads delegated algorithms from properties or defaults.
    */
   private static Map<String, Set<String>> loadDelegatedAlgorithms() {
      Map<String, Set<String>> result = new HashMap<>();

      // Start with defaults
      for (Map.Entry<String, Set<String>> entry : DEFAULT_DELEGATED_ALGORITHMS.entrySet()) {
         result.put(entry.getKey(), new HashSet<>(entry.getValue()));
      }

      // Check for custom overrides via system properties
      for (String serviceType : DEFAULT_DELEGATED_ALGORITHMS.keySet()) {
         String customValue = getProperty(HYBRID_DELEGATE_PREFIX + serviceType);
         if (customValue != null) {
            result.put(serviceType, parseAlgorithmList(customValue));
         }
      }

      // Check for additional service types not in defaults
      // (Allow users to extend to other service types)
      String[] otherServiceTypes = {"Cipher", "Signature", "KeyAgreement", "KeyFactory"};
      for (String serviceType : otherServiceTypes) {
         String customValue = getProperty(HYBRID_DELEGATE_PREFIX + serviceType);
         if (customValue != null) {
            result.put(serviceType, parseAlgorithmList(customValue));
         }
      }

      // Make all sets unmodifiable
      Map<String, Set<String>> unmodifiable = new HashMap<>();
      for (Map.Entry<String, Set<String>> entry : result.entrySet()) {
         unmodifiable.put(entry.getKey(), Collections.unmodifiableSet(entry.getValue()));
      }

      return Collections.unmodifiableMap(unmodifiable);
   }

   /**
    * Gets a property from system properties first, then Security properties.
    */
   private static String getProperty(String key) {
      String value = System.getProperty(key);
      if (value != null) {
         return value;
      }
      return Security.getProperty(key);
   }

   /**
    * Parses a comma-separated list of algorithm names.
    */
   private static Set<String> parseAlgorithmList(String value) {
      Set<String> algorithms = new HashSet<>();
      if (value == null || value.trim().isEmpty()) {
         return algorithms;
      }
      for (String algo : value.split(",")) {
         String trimmed = algo.trim();
         if (!trimmed.isEmpty()) {
            algorithms.add(trimmed);
         }
      }
      return algorithms;
   }

   /**
    * Clears the cached configuration.
    * This is primarily useful for testing.
    */
   public static void clearCache() {
      synchronized (HybridModeConfig.class) {
         cachedHybridEnabled = null;
         cachedDelegatedAlgorithms = null;
      }
   }

   /**
    * Returns a human-readable description of the current hybrid mode configuration.
    *
    * @return configuration description string
    */
   public static String getConfigDescription() {
      StringBuilder sb = new StringBuilder();
      sb.append("Hybrid Mode: ").append(isHybridEnabled() ? "ENABLED" : "DISABLED");

      if (isHybridEnabled()) {
         sb.append("\nDelegated Algorithms:");
         Map<String, Set<String>> delegated = getAllDelegatedAlgorithms();
         for (Map.Entry<String, Set<String>> entry : delegated.entrySet()) {
            if (!entry.getValue().isEmpty()) {
               sb.append("\n  ").append(entry.getKey()).append(": ");
               sb.append(String.join(", ", entry.getValue()));
            }
         }
      }

      String sysProp = System.getProperty(HYBRID_ENABLED_PROPERTY);
      if (sysProp != null) {
         sb.append("\n  System property override: ").append(sysProp);
      }

      String secProp = Security.getProperty(HYBRID_ENABLED_PROPERTY);
      if (secProp != null) {
         sb.append("\n  Security property: ").append(secProp);
      }

      return sb.toString();
   }
}
