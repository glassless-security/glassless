package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class HybridModeConfigTest {

   private String originalHybridEnabled;
   private String originalMessageDigestDelegate;
   private String originalMacDelegate;
   private String originalSecureRandomDelegate;
   private String originalKemDelegate;
   private String originalKeyPairGeneratorDelegate;

   @BeforeEach
   public void setUp() {
      // Save original property values
      originalHybridEnabled = System.getProperty("glassless.hybrid.enabled");
      originalMessageDigestDelegate = System.getProperty("glassless.hybrid.delegate.MessageDigest");
      originalMacDelegate = System.getProperty("glassless.hybrid.delegate.Mac");
      originalSecureRandomDelegate = System.getProperty("glassless.hybrid.delegate.SecureRandom");
      originalKemDelegate = System.getProperty("glassless.hybrid.delegate.KEM");
      originalKeyPairGeneratorDelegate = System.getProperty("glassless.hybrid.delegate.KeyPairGenerator");

      // Clear all properties before each test
      clearHybridProperties();
      HybridModeConfig.clearCache();
   }

   @AfterEach
   public void tearDown() {
      // Restore original property values
      restoreProperty("glassless.hybrid.enabled", originalHybridEnabled);
      restoreProperty("glassless.hybrid.delegate.MessageDigest", originalMessageDigestDelegate);
      restoreProperty("glassless.hybrid.delegate.Mac", originalMacDelegate);
      restoreProperty("glassless.hybrid.delegate.SecureRandom", originalSecureRandomDelegate);
      restoreProperty("glassless.hybrid.delegate.KEM", originalKemDelegate);
      restoreProperty("glassless.hybrid.delegate.KeyPairGenerator", originalKeyPairGeneratorDelegate);
      HybridModeConfig.clearCache();
   }

   private void clearHybridProperties() {
      System.clearProperty("glassless.hybrid.enabled");
      System.clearProperty("glassless.hybrid.delegate.MessageDigest");
      System.clearProperty("glassless.hybrid.delegate.Mac");
      System.clearProperty("glassless.hybrid.delegate.SecureRandom");
      System.clearProperty("glassless.hybrid.delegate.KEM");
      System.clearProperty("glassless.hybrid.delegate.KeyPairGenerator");
   }

   private void restoreProperty(String key, String value) {
      if (value != null) {
         System.setProperty(key, value);
      } else {
         System.clearProperty(key);
      }
   }

   @Nested
   @DisplayName("Hybrid Mode Enable/Disable Tests")
   class EnableDisableTests {

      @Test
      @DisplayName("Hybrid mode is disabled by default")
      void testDisabledByDefault() {
         assertFalse(HybridModeConfig.isHybridEnabled());
      }

      @Test
      @DisplayName("System property enables hybrid mode")
      void testSystemPropertyEnables() {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         assertTrue(HybridModeConfig.isHybridEnabled());
      }

      @Test
      @DisplayName("System property disables hybrid mode")
      void testSystemPropertyDisables() {
         System.setProperty("glassless.hybrid.enabled", "false");
         HybridModeConfig.clearCache();

         assertFalse(HybridModeConfig.isHybridEnabled());
      }

      @Test
      @DisplayName("System property is case-insensitive")
      void testSystemPropertyCaseInsensitive() {
         System.setProperty("glassless.hybrid.enabled", "TRUE");
         HybridModeConfig.clearCache();
         assertTrue(HybridModeConfig.isHybridEnabled());

         System.setProperty("glassless.hybrid.enabled", "True");
         HybridModeConfig.clearCache();
         assertTrue(HybridModeConfig.isHybridEnabled());

         System.setProperty("glassless.hybrid.enabled", "FALSE");
         HybridModeConfig.clearCache();
         assertFalse(HybridModeConfig.isHybridEnabled());
      }

      @Test
      @DisplayName("Invalid system property value defaults to disabled")
      void testInvalidSystemPropertyValue() {
         System.setProperty("glassless.hybrid.enabled", "invalid");
         HybridModeConfig.clearCache();

         assertFalse(HybridModeConfig.isHybridEnabled());
      }

      @Test
      @DisplayName("Security property enables hybrid mode")
      void testSecurityPropertyEnables() {
         Security.setProperty("glassless.hybrid.enabled", "true");
         try {
            HybridModeConfig.clearCache();
            assertTrue(HybridModeConfig.isHybridEnabled());
         } finally {
            Security.setProperty("glassless.hybrid.enabled", "");
         }
      }

      @Test
      @DisplayName("System property takes precedence over Security property")
      void testSystemPropertyPrecedence() {
         Security.setProperty("glassless.hybrid.enabled", "true");
         System.setProperty("glassless.hybrid.enabled", "false");

         try {
            HybridModeConfig.clearCache();
            assertFalse(HybridModeConfig.isHybridEnabled());
         } finally {
            Security.setProperty("glassless.hybrid.enabled", "");
         }
      }
   }

   @Nested
   @DisplayName("Default Delegated Algorithms Tests")
   class DefaultDelegatedAlgorithmsTests {

      @Test
      @DisplayName("Default MessageDigest algorithms include SHA-256 and SHA-512")
      void testDefaultMessageDigestAlgorithms() {
         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("MessageDigest");

         assertTrue(algorithms.contains("SHA-256"));
         assertTrue(algorithms.contains("SHA-512"));
      }

      @Test
      @DisplayName("Default Mac algorithms include HmacSHA256 and HmacSHA512")
      void testDefaultMacAlgorithms() {
         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("Mac");

         assertTrue(algorithms.contains("HmacSHA256"));
         assertTrue(algorithms.contains("HmacSHA512"));
      }

      @Test
      @DisplayName("Default SecureRandom algorithms include NativePRNG and DRBG")
      void testDefaultSecureRandomAlgorithms() {
         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("SecureRandom");

         assertTrue(algorithms.contains("NativePRNG"));
         assertTrue(algorithms.contains("DRBG"));
      }

      @Test
      @DisplayName("Default KEM algorithms include ML-KEM variants")
      void testDefaultKemAlgorithms() {
         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("KEM");

         assertTrue(algorithms.contains("ML-KEM"));
         assertTrue(algorithms.contains("ML-KEM-512"));
         assertTrue(algorithms.contains("ML-KEM-768"));
         assertTrue(algorithms.contains("ML-KEM-1024"));
      }

      @Test
      @DisplayName("Default KeyPairGenerator algorithms include ML-KEM variants")
      void testDefaultKeyPairGeneratorAlgorithms() {
         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("KeyPairGenerator");

         assertTrue(algorithms.contains("ML-KEM"));
         assertTrue(algorithms.contains("ML-KEM-512"));
         assertTrue(algorithms.contains("ML-KEM-768"));
         assertTrue(algorithms.contains("ML-KEM-1024"));
      }

      @Test
      @DisplayName("Unknown service type returns empty set")
      void testUnknownServiceType() {
         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("Unknown");

         assertNotNull(algorithms);
         assertTrue(algorithms.isEmpty());
      }
   }

   @Nested
   @DisplayName("shouldDelegate Tests")
   class ShouldDelegateTests {

      @Test
      @DisplayName("shouldDelegate returns true for exact algorithm match")
      void testExactMatch() {
         assertTrue(HybridModeConfig.shouldDelegate("MessageDigest", "SHA-256"));
         assertTrue(HybridModeConfig.shouldDelegate("Mac", "HmacSHA256"));
      }

      @Test
      @DisplayName("shouldDelegate returns false for non-delegated algorithm")
      void testNonDelegatedAlgorithm() {
         assertFalse(HybridModeConfig.shouldDelegate("MessageDigest", "MD5"));
         assertFalse(HybridModeConfig.shouldDelegate("MessageDigest", "SHA-1"));
         assertFalse(HybridModeConfig.shouldDelegate("Mac", "HmacSHA1"));
      }

      @Test
      @DisplayName("shouldDelegate handles algorithm name variations")
      void testAlgorithmNameVariations() {
         // SHA256 vs SHA-256
         assertTrue(HybridModeConfig.shouldDelegate("MessageDigest", "SHA256"));
         assertTrue(HybridModeConfig.shouldDelegate("MessageDigest", "sha-256"));
         assertTrue(HybridModeConfig.shouldDelegate("MessageDigest", "sha256"));
      }

      @Test
      @DisplayName("shouldDelegate returns false for unknown service type")
      void testUnknownServiceType() {
         assertFalse(HybridModeConfig.shouldDelegate("Unknown", "SHA-256"));
      }
   }

   @Nested
   @DisplayName("Custom Algorithm List Tests")
   class CustomAlgorithmListTests {

      @Test
      @DisplayName("Custom MessageDigest algorithm list overrides defaults")
      void testCustomMessageDigestOverride() {
         System.setProperty("glassless.hybrid.delegate.MessageDigest", "SHA-384,SHA3-256");
         HybridModeConfig.clearCache();

         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("MessageDigest");

         assertTrue(algorithms.contains("SHA-384"));
         assertTrue(algorithms.contains("SHA3-256"));
         assertFalse(algorithms.contains("SHA-256")); // Default is overridden
         assertFalse(algorithms.contains("SHA-512")); // Default is overridden
      }

      @Test
      @DisplayName("Custom Mac algorithm list overrides defaults")
      void testCustomMacOverride() {
         System.setProperty("glassless.hybrid.delegate.Mac", "HmacSHA384");
         HybridModeConfig.clearCache();

         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("Mac");

         assertTrue(algorithms.contains("HmacSHA384"));
         assertFalse(algorithms.contains("HmacSHA256")); // Default is overridden
      }

      @Test
      @DisplayName("Empty custom list results in empty set")
      void testEmptyCustomList() {
         System.setProperty("glassless.hybrid.delegate.MessageDigest", "");
         HybridModeConfig.clearCache();

         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("MessageDigest");

         assertTrue(algorithms.isEmpty());
      }

      @Test
      @DisplayName("Custom list handles whitespace correctly")
      void testCustomListWithWhitespace() {
         System.setProperty("glassless.hybrid.delegate.MessageDigest", " SHA-256 , SHA-384 , SHA-512 ");
         HybridModeConfig.clearCache();

         Set<String> algorithms = HybridModeConfig.getDelegatedAlgorithms("MessageDigest");

         assertTrue(algorithms.contains("SHA-256"));
         assertTrue(algorithms.contains("SHA-384"));
         assertTrue(algorithms.contains("SHA-512"));
      }
   }

   @Nested
   @DisplayName("Configuration Description Tests")
   class ConfigDescriptionTests {

      @Test
      @DisplayName("Config description shows disabled state")
      void testDisabledDescription() {
         String description = HybridModeConfig.getConfigDescription();

         assertTrue(description.contains("Hybrid Mode: DISABLED"));
      }

      @Test
      @DisplayName("Config description shows enabled state and algorithms")
      void testEnabledDescription() {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         String description = HybridModeConfig.getConfigDescription();

         assertTrue(description.contains("Hybrid Mode: ENABLED"));
         assertTrue(description.contains("Delegated Algorithms"));
         assertTrue(description.contains("MessageDigest"));
      }

      @Test
      @DisplayName("Config description shows system property override")
      void testDescriptionShowsSystemProperty() {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         String description = HybridModeConfig.getConfigDescription();

         assertTrue(description.contains("System property override: true"));
      }
   }

   @Nested
   @DisplayName("Cache Behavior Tests")
   class CacheBehaviorTests {

      @Test
      @DisplayName("Values are cached after first call")
      void testCaching() {
         // First call
         assertFalse(HybridModeConfig.isHybridEnabled());

         // Change property (should be ignored due to caching)
         System.setProperty("glassless.hybrid.enabled", "true");

         // Should still return cached value
         assertFalse(HybridModeConfig.isHybridEnabled());

         // Clear cache and verify new value is picked up
         HybridModeConfig.clearCache();
         assertTrue(HybridModeConfig.isHybridEnabled());
      }

      @Test
      @DisplayName("clearCache resets all cached values")
      void testClearCache() {
         // Initial state
         assertFalse(HybridModeConfig.isHybridEnabled());

         // Enable hybrid mode
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         assertTrue(HybridModeConfig.isHybridEnabled());

         // Disable and clear
         System.setProperty("glassless.hybrid.enabled", "false");
         HybridModeConfig.clearCache();

         assertFalse(HybridModeConfig.isHybridEnabled());
      }
   }
}
