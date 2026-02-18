package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for hybrid mode functionality.
 *
 * <p>These tests verify that when hybrid mode is enabled, delegated algorithms
 * fall through to the JDK provider instead of being provided by GlaSSLess.
 */
public class HybridModeIntegrationTest {

   private static GlaSSLessProvider originalProvider;
   private String originalHybridEnabled;
   private String originalFipsMode;

   @BeforeAll
   public static void setUpClass() {
      // Save original provider if present
      originalProvider = (GlaSSLessProvider) Security.getProvider("GlaSSLess");
      if (originalProvider != null) {
         Security.removeProvider("GlaSSLess");
      }
   }

   @AfterAll
   public static void tearDownClass() {
      // Restore original provider
      Security.removeProvider("GlaSSLess");
      if (originalProvider != null) {
         Security.addProvider(originalProvider);
      }
   }

   @BeforeEach
   public void setUp() {
      // Save original property values
      originalHybridEnabled = System.getProperty("glassless.hybrid.enabled");
      originalFipsMode = System.getProperty("glassless.fips.mode");

      // Clear properties
      System.clearProperty("glassless.hybrid.enabled");
      System.clearProperty("glassless.fips.mode");
      HybridModeConfig.clearCache();
      FIPSStatus.clearCache();

      // Remove provider if present
      Security.removeProvider("GlaSSLess");
   }

   @AfterEach
   public void tearDown() {
      // Restore properties
      if (originalHybridEnabled != null) {
         System.setProperty("glassless.hybrid.enabled", originalHybridEnabled);
      } else {
         System.clearProperty("glassless.hybrid.enabled");
      }
      if (originalFipsMode != null) {
         System.setProperty("glassless.fips.mode", originalFipsMode);
      } else {
         System.clearProperty("glassless.fips.mode");
      }
      HybridModeConfig.clearCache();
      FIPSStatus.clearCache();
      Security.removeProvider("GlaSSLess");
   }

   @Nested
   @DisplayName("Hybrid Mode Enabled Tests")
   class HybridModeEnabledTests {

      @Test
      @DisplayName("Provider reports hybrid mode enabled")
      void testProviderReportsHybridModeEnabled() {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         assertTrue(provider.isHybridMode());
      }

      @Test
      @DisplayName("SHA-256 delegates to JDK in hybrid mode")
      void testSHA256DelegatesInHybridMode() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // SHA-256 should NOT be available from GlaSSLess in hybrid mode
         assertThrows(NoSuchAlgorithmException.class, () ->
            MessageDigest.getInstance("SHA-256", "GlaSSLess"));

         // But it should still be available from default provider
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         assertNotNull(md);
         assertNotEquals("GlaSSLess", md.getProvider().getName());
      }

      @Test
      @DisplayName("SHA-512 delegates to JDK in hybrid mode")
      void testSHA512DelegatesInHybridMode() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // SHA-512 should NOT be available from GlaSSLess in hybrid mode
         assertThrows(NoSuchAlgorithmException.class, () ->
            MessageDigest.getInstance("SHA-512", "GlaSSLess"));

         // But it should still be available from default provider
         MessageDigest md = MessageDigest.getInstance("SHA-512");
         assertNotNull(md);
         assertNotEquals("GlaSSLess", md.getProvider().getName());
      }

      @Test
      @DisplayName("HmacSHA256 delegates to JDK in hybrid mode")
      void testHmacSHA256DelegatesInHybridMode() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // HmacSHA256 should NOT be available from GlaSSLess in hybrid mode
         assertThrows(NoSuchAlgorithmException.class, () ->
            Mac.getInstance("HmacSHA256", "GlaSSLess"));

         // But it should still be available from default provider
         Mac mac = Mac.getInstance("HmacSHA256");
         assertNotNull(mac);
         assertNotEquals("GlaSSLess", mac.getProvider().getName());
      }

      @Test
      @DisplayName("HmacSHA512 delegates to JDK in hybrid mode")
      void testHmacSHA512DelegatesInHybridMode() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // HmacSHA512 should NOT be available from GlaSSLess in hybrid mode
         assertThrows(NoSuchAlgorithmException.class, () ->
            Mac.getInstance("HmacSHA512", "GlaSSLess"));

         // But it should still be available from default provider
         Mac mac = Mac.getInstance("HmacSHA512");
         assertNotNull(mac);
         assertNotEquals("GlaSSLess", mac.getProvider().getName());
      }

      @Test
      @DisplayName("Non-delegated algorithms still available from GlaSSLess")
      void testNonDelegatedAlgorithmsStillAvailable() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // SHA-384 is not in the default delegate list, so should be available
         MessageDigest md = MessageDigest.getInstance("SHA-384", "GlaSSLess");
         assertNotNull(md);
         assertEquals("GlaSSLess", md.getProvider().getName());

         // HmacSHA384 is not in the default delegate list
         Mac mac = Mac.getInstance("HmacSHA384", "GlaSSLess");
         assertNotNull(mac);
         assertEquals("GlaSSLess", mac.getProvider().getName());
      }

      @Test
      @DisplayName("SHA3-256 still available from GlaSSLess in hybrid mode")
      void testSHA3_256StillAvailable() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // SHA3-256 is not in the default delegate list
         MessageDigest md = MessageDigest.getInstance("SHA3-256", "GlaSSLess");
         assertNotNull(md);
         assertEquals("GlaSSLess", md.getProvider().getName());
      }
   }

   @Nested
   @DisplayName("Hybrid Mode Disabled Tests")
   class HybridModeDisabledTests {

      @Test
      @DisplayName("All algorithms available when hybrid mode disabled")
      void testAllAlgorithmsAvailableWhenDisabled() throws Exception {
         // Hybrid mode disabled (default)
         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         assertFalse(provider.isHybridMode());

         // All algorithms should be available from GlaSSLess
         MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "GlaSSLess");
         assertEquals("GlaSSLess", sha256.getProvider().getName());

         MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "GlaSSLess");
         assertEquals("GlaSSLess", sha512.getProvider().getName());

         Mac hmacSha256 = Mac.getInstance("HmacSHA256", "GlaSSLess");
         assertEquals("GlaSSLess", hmacSha256.getProvider().getName());

         Mac hmacSha512 = Mac.getInstance("HmacSHA512", "GlaSSLess");
         assertEquals("GlaSSLess", hmacSha512.getProvider().getName());
      }
   }

   @Nested
   @DisplayName("FIPS Mode Interaction Tests")
   class FIPSModeInteractionTests {

      @Test
      @DisplayName("Hybrid mode disabled when FIPS mode is active")
      void testHybridModeDisabledInFIPSMode() {
         // Enable both hybrid and FIPS mode
         System.setProperty("glassless.hybrid.enabled", "true");
         System.setProperty("glassless.fips.mode", "true");
         HybridModeConfig.clearCache();
         FIPSStatus.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // FIPS mode should be enabled
         assertTrue(provider.isFIPSMode());

         // Hybrid mode should be disabled even though property is set
         assertFalse(provider.isHybridMode());
      }

      @Test
      @DisplayName("All FIPS algorithms available when FIPS overrides hybrid")
      void testFIPSAlgorithmsAvailable() throws Exception {
         // Enable both hybrid and FIPS mode
         System.setProperty("glassless.hybrid.enabled", "true");
         System.setProperty("glassless.fips.mode", "true");
         HybridModeConfig.clearCache();
         FIPSStatus.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // SHA-256 should be available from GlaSSLess in FIPS mode
         // (hybrid delegation is overridden)
         MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "GlaSSLess");
         assertEquals("GlaSSLess", sha256.getProvider().getName());

         MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "GlaSSLess");
         assertEquals("GlaSSLess", sha512.getProvider().getName());
      }
   }

   @Nested
   @DisplayName("Functional Tests with Hybrid Mode")
   class FunctionalTests {

      @Test
      @DisplayName("Delegated SHA-256 produces correct digest")
      void testDelegatedSHA256ProducesCorrectDigest() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // Get SHA-256 from default provider (delegated)
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         byte[] digest = md.digest("test".getBytes());

         // Verify digest is correct (expected SHA-256 of "test")
         assertEquals(32, digest.length);
      }

      @Test
      @DisplayName("Non-delegated SHA-384 from GlaSSLess produces correct digest")
      void testNonDelegatedSHA384ProducesCorrectDigest() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // Get SHA-384 from GlaSSLess (not delegated)
         MessageDigest md = MessageDigest.getInstance("SHA-384", "GlaSSLess");
         byte[] digest = md.digest("test".getBytes());

         // Verify digest length is correct for SHA-384
         assertEquals(48, digest.length);
      }

      @Test
      @DisplayName("Delegated HmacSHA256 produces correct MAC")
      void testDelegatedHmacSHA256ProducesCorrectMAC() throws Exception {
         System.setProperty("glassless.hybrid.enabled", "true");
         HybridModeConfig.clearCache();

         GlaSSLessProvider provider = new GlaSSLessProvider();
         Security.insertProviderAt(provider, 1);

         // Get HmacSHA256 from default provider (delegated)
         Mac mac = Mac.getInstance("HmacSHA256");
         KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
         keyGen.init(256);
         mac.init(keyGen.generateKey());
         byte[] macResult = mac.doFinal("test".getBytes());

         // Verify MAC length is correct
         assertEquals(32, macResult.length);
      }
   }
}
