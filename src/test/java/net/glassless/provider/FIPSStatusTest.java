package net.glassless.provider;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class FIPSStatusTest {

   private static GlaSSLessProvider provider;

   @BeforeAll
   public static void setUp() {
      // Clear any cached FIPS status
      FIPSStatus.clearCache();
      provider = new GlaSSLessProvider();
      Security.addProvider(provider);
   }

   @AfterEach
   public void tearDown() {
      // Clear cache after each test
      FIPSStatus.clearCache();
   }

   @Nested
   @DisplayName("FIPSStatus Detection Tests")
   class DetectionTests {

      @Test
      @DisplayName("FIPS status can be queried")
      void testFIPSStatusQuery() {
         // Should not throw, result depends on OpenSSL configuration
         var _ = FIPSStatus.isFIPSEnabled();
      }

      @Test
      @DisplayName("FIPS provider availability can be queried")
      void testFIPSProviderAvailability() {
         // Should not throw, result depends on OpenSSL configuration
         var _ = FIPSStatus.isFIPSProviderAvailable();
      }

      @Test
      @DisplayName("Status description is available")
      void testStatusDescription() {
         String description = FIPSStatus.getStatusDescription();
         assertNotNull(description);
         assertTrue(description.contains("FIPS Mode:"));
      }

      @Test
      @DisplayName("System property can override FIPS mode")
      void testSystemPropertyOverride() {
         // Save original
         String original = System.getProperty("glassless.fips.mode");

         try {
            // Test true override
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();
            assertTrue(FIPSStatus.isFIPSEnabled());

            // Test false override
            System.setProperty("glassless.fips.mode", "false");
            FIPSStatus.clearCache();
            assertFalse(FIPSStatus.isFIPSEnabled());
         } finally {
            // Restore original
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();
         }
      }
   }

   @Nested
   @DisplayName("Non-FIPS Mode Algorithm Availability Tests")
   class NonFIPSModeTests {

      @Test
      @DisplayName("MD5 is available in non-FIPS mode")
      void testMD5Available() throws Exception {
         // If not in FIPS mode, MD5 should be available
         if (!FIPSStatus.isFIPSEnabled()) {
            MessageDigest md = MessageDigest.getInstance("MD5", PROVIDER_NAME);
            assertNotNull(md);
         }
      }

      @Test
      @DisplayName("SHA-1 is available in non-FIPS mode")
      void testSHA1Available() throws Exception {
         if (!FIPSStatus.isFIPSEnabled()) {
            MessageDigest md = MessageDigest.getInstance("SHA-1", PROVIDER_NAME);
            assertNotNull(md);
         }
      }

      @Test
      @DisplayName("ChaCha20-Poly1305 is available in non-FIPS mode")
      void testChaCha20Poly1305Available() throws Exception {
         if (!FIPSStatus.isFIPSEnabled()) {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", PROVIDER_NAME);
            assertNotNull(cipher);
         }
      }

      @Test
      @DisplayName("DESede is available in non-FIPS mode")
      void testDESedeAvailable() throws Exception {
         if (!FIPSStatus.isFIPSEnabled()) {
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVIDER_NAME);
            assertNotNull(cipher);
         }
      }

      @Test
      @DisplayName("SCRYPT is available in non-FIPS mode")
      void testSCRYPTAvailable() throws Exception {
         if (!FIPSStatus.isFIPSEnabled()) {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", PROVIDER_NAME);
            assertNotNull(skf);
         }
      }
   }

   @Nested
   @DisplayName("FIPS-Approved Algorithm Availability Tests")
   class FIPSApprovedTests {

      @Test
      @DisplayName("SHA-256 is always available")
      void testSHA256Available() throws Exception {
         MessageDigest md = MessageDigest.getInstance("SHA-256", PROVIDER_NAME);
         assertNotNull(md);
      }

      @Test
      @DisplayName("SHA-512 is always available")
      void testSHA512Available() throws Exception {
         MessageDigest md = MessageDigest.getInstance("SHA-512", PROVIDER_NAME);
         assertNotNull(md);
      }

      @Test
      @DisplayName("SHA3-256 is always available")
      void testSHA3_256Available() throws Exception {
         MessageDigest md = MessageDigest.getInstance("SHA3-256", PROVIDER_NAME);
         assertNotNull(md);
      }

      @Test
      @DisplayName("AES is always available")
      void testAESAvailable() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", PROVIDER_NAME);
         assertNotNull(cipher);
      }

      @Test
      @DisplayName("PBKDF2WithHmacSHA256 is always available")
      void testPBKDF2Available() throws Exception {
         SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", PROVIDER_NAME);
         assertNotNull(skf);
      }
   }

   @Nested
   @DisplayName("Provider FIPS Mode Reporting Tests")
   class ProviderFIPSModeTests {

      @Test
      @DisplayName("Provider reports FIPS mode status")
      void testProviderReportsFIPSMode() {
         GlaSSLessProvider gp = new GlaSSLessProvider();
         // Should match FIPSStatus
         assertEquals(FIPSStatus.isFIPSEnabled(), gp.isFIPSMode());
      }
   }

   @Nested
   @DisplayName("Simulated FIPS Mode Algorithm Restriction Tests")
   class SimulatedFIPSModeTests {

      @Test
      @DisplayName("In simulated FIPS mode, MD5 is not available")
      void testMD5NotAvailableInFIPSMode() {
         String original = System.getProperty("glassless.fips.mode");
         try {
            // Simulate FIPS mode
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();

            // Remove and re-add provider to pick up new FIPS status
            Security.removeProvider(PROVIDER_NAME);
            GlaSSLessProvider fipsProvider = new GlaSSLessProvider();
            Security.addProvider(fipsProvider);

            assertTrue(fipsProvider.isFIPSMode(), "Provider should be in FIPS mode");

            // MD5 should not be available
            assertThrows(NoSuchAlgorithmException.class, () -> MessageDigest.getInstance("MD5", PROVIDER_NAME));
         } finally {
            // Restore
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();

            // Restore original provider
            Security.removeProvider(PROVIDER_NAME);
            Security.addProvider(provider);
         }
      }

      @Test
      @DisplayName("In simulated FIPS mode, ChaCha20-Poly1305 is not available")
      void testChaCha20NotAvailableInFIPSMode() {
         String original = System.getProperty("glassless.fips.mode");
         try {
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();

            Security.removeProvider(PROVIDER_NAME);
            GlaSSLessProvider fipsProvider = new GlaSSLessProvider();
            Security.addProvider(fipsProvider);

            assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance("ChaCha20-Poly1305", PROVIDER_NAME));
         } finally {
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();
            Security.removeProvider(PROVIDER_NAME);
            Security.addProvider(provider);
         }
      }

      @Test
      @DisplayName("In simulated FIPS mode, SCRYPT is not available")
      void testSCRYPTNotAvailableInFIPSMode() {
         String original = System.getProperty("glassless.fips.mode");
         try {
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();

            Security.removeProvider(PROVIDER_NAME);
            GlaSSLessProvider fipsProvider = new GlaSSLessProvider();
            Security.addProvider(fipsProvider);

            assertThrows(NoSuchAlgorithmException.class, () -> SecretKeyFactory.getInstance("SCRYPT", PROVIDER_NAME));
         } finally {
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();
            Security.removeProvider(PROVIDER_NAME);
            Security.addProvider(provider);
         }
      }

      @Test
      @DisplayName("In simulated FIPS mode, SHA-256 is still available")
      void testSHA256AvailableInFIPSMode() throws Exception {
         String original = System.getProperty("glassless.fips.mode");
         try {
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();

            Security.removeProvider(PROVIDER_NAME);
            GlaSSLessProvider fipsProvider = new GlaSSLessProvider();
            Security.addProvider(fipsProvider);

            // SHA-256 should still be available
            MessageDigest md = MessageDigest.getInstance("SHA-256", PROVIDER_NAME);
            assertNotNull(md);
         } finally {
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();
            Security.removeProvider(PROVIDER_NAME);
            Security.addProvider(provider);
         }
      }

      @Test
      @DisplayName("In simulated FIPS mode, AES-GCM is still available")
      void testAESGCMAvailableInFIPSMode() throws Exception {
         String original = System.getProperty("glassless.fips.mode");
         try {
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();

            Security.removeProvider(PROVIDER_NAME);
            GlaSSLessProvider fipsProvider = new GlaSSLessProvider();
            Security.addProvider(fipsProvider);

            // AES-GCM should still be available
            Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", PROVIDER_NAME);
            assertNotNull(cipher);
         } finally {
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();
            Security.removeProvider(PROVIDER_NAME);
            Security.addProvider(provider);
         }
      }
   }

   @Nested
   @DisplayName("FIPS Mode Runtime Enforcement Tests")
   class FIPSRuntimeEnforcementTests {

      private void withSimulatedFIPSMode(ThrowingRunnable test) throws Exception {
         String original = System.getProperty("glassless.fips.mode");
         try {
            System.setProperty("glassless.fips.mode", "true");
            FIPSStatus.clearCache();

            Security.removeProvider(PROVIDER_NAME);
            GlaSSLessProvider fipsProvider = new GlaSSLessProvider();
            Security.addProvider(fipsProvider);

            test.run();
         } finally {
            if (original != null) {
               System.setProperty("glassless.fips.mode", original);
            } else {
               System.clearProperty("glassless.fips.mode");
            }
            FIPSStatus.clearCache();
            Security.removeProvider(PROVIDER_NAME);
            Security.addProvider(provider);
         }
      }

      @FunctionalInterface
      interface ThrowingRunnable {
         void run() throws Exception;
      }

      // --- EC curve whitelist tests ---

      @Test
      @DisplayName("FIPS mode allows P-256")
      void testFIPSAllowsP256() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            assertNotNull(kpg.generateKeyPair());
         });
      }

      @Test
      @DisplayName("FIPS mode allows P-384")
      void testFIPSAllowsP384() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp384r1"));
            assertNotNull(kpg.generateKeyPair());
         });
      }

      @Test
      @DisplayName("FIPS mode allows P-521")
      void testFIPSAllowsP521() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp521r1"));
            assertNotNull(kpg.generateKeyPair());
         });
      }

      @Test
      @DisplayName("FIPS mode rejects secp256k1")
      void testFIPSRejectsSecp256k1() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            assertThrows(InvalidAlgorithmParameterException.class,
               () -> kpg.initialize(new ECGenParameterSpec("secp256k1")));
         });
      }

      @Test
      @DisplayName("FIPS mode rejects arbitrary curves")
      void testFIPSRejectsArbitraryCurves() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            assertThrows(InvalidAlgorithmParameterException.class,
               () -> kpg.initialize(new ECGenParameterSpec("brainpoolP256r1")));
         });
      }

      // --- RSA key size enforcement tests ---

      @Test
      @DisplayName("FIPS mode allows RSA 2048")
      void testFIPSAllowsRSA2048() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            kpg.initialize(2048);
            assertNotNull(kpg.generateKeyPair());
         });
      }

      @Test
      @DisplayName("FIPS mode rejects RSA 1024")
      void testFIPSRejectsRSA1024() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            assertThrows(InvalidParameterException.class,
               () -> kpg.initialize(1024));
         });
      }

      @Test
      @DisplayName("FIPS mode rejects RSA 512")
      void testFIPSRejectsRSA512() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            assertThrows(InvalidParameterException.class,
               () -> kpg.initialize(512));
         });
      }

      // --- DSA key size enforcement tests ---

      @Test
      @DisplayName("FIPS mode allows DSA 2048")
      void testFIPSAllowsDSA2048() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", PROVIDER_NAME);
            kpg.initialize(2048);
            // Just verify initialization succeeds (keygen is slow for DSA)
         });
      }

      @Test
      @DisplayName("FIPS mode rejects DSA 1024")
      void testFIPSRejectsDSA1024() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", PROVIDER_NAME);
            assertThrows(InvalidParameterException.class,
               () -> kpg.initialize(1024));
         });
      }

      // --- DH key size enforcement tests ---

      @Test
      @DisplayName("FIPS mode allows DH 2048")
      void testFIPSAllowsDH2048() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", PROVIDER_NAME);
            kpg.initialize(2048);
            // Just verify initialization succeeds (keygen is slow for DH)
         });
      }

      @Test
      @DisplayName("FIPS mode rejects DH 1024")
      void testFIPSRejectsDH1024() throws Exception {
         withSimulatedFIPSMode(() -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", PROVIDER_NAME);
            assertThrows(InvalidParameterException.class,
               () -> kpg.initialize(1024));
         });
      }
   }
}
