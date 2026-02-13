package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class FIPSStatusTest {

    private static GlasslessProvider provider;

    @BeforeAll
    public static void setUp() {
        // Clear any cached FIPS status
        FIPSStatus.clearCache();
        provider = new GlasslessProvider();
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
            // Should not throw
            boolean fipsEnabled = FIPSStatus.isFIPSEnabled();
            // The result depends on the system configuration
            assertNotNull(Boolean.valueOf(fipsEnabled));
        }

        @Test
        @DisplayName("FIPS provider availability can be queried")
        void testFIPSProviderAvailability() {
            // Should not throw
            boolean available = FIPSStatus.isFIPSProviderAvailable();
            assertNotNull(Boolean.valueOf(available));
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
                MessageDigest md = MessageDigest.getInstance("MD5", "Glassless");
                assertNotNull(md);
            }
        }

        @Test
        @DisplayName("SHA-1 is available in non-FIPS mode")
        void testSHA1Available() throws Exception {
            if (!FIPSStatus.isFIPSEnabled()) {
                MessageDigest md = MessageDigest.getInstance("SHA-1", "Glassless");
                assertNotNull(md);
            }
        }

        @Test
        @DisplayName("ChaCha20-Poly1305 is available in non-FIPS mode")
        void testChaCha20Poly1305Available() throws Exception {
            if (!FIPSStatus.isFIPSEnabled()) {
                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "Glassless");
                assertNotNull(cipher);
            }
        }

        @Test
        @DisplayName("DESede is available in non-FIPS mode")
        void testDESedeAvailable() throws Exception {
            if (!FIPSStatus.isFIPSEnabled()) {
                Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "Glassless");
                assertNotNull(cipher);
            }
        }

        @Test
        @DisplayName("SCRYPT is available in non-FIPS mode")
        void testSCRYPTAvailable() throws Exception {
            if (!FIPSStatus.isFIPSEnabled()) {
                SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "Glassless");
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
            MessageDigest md = MessageDigest.getInstance("SHA-256", "Glassless");
            assertNotNull(md);
        }

        @Test
        @DisplayName("SHA-512 is always available")
        void testSHA512Available() throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-512", "Glassless");
            assertNotNull(md);
        }

        @Test
        @DisplayName("SHA3-256 is always available")
        void testSHA3_256Available() throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA3-256", "Glassless");
            assertNotNull(md);
        }

        @Test
        @DisplayName("AES is always available")
        void testAESAvailable() throws Exception {
            Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "Glassless");
            assertNotNull(cipher);
        }

        @Test
        @DisplayName("PBKDF2WithHmacSHA256 is always available")
        void testPBKDF2Available() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "Glassless");
            assertNotNull(skf);
        }
    }

    @Nested
    @DisplayName("Provider FIPS Mode Reporting Tests")
    class ProviderFIPSModeTests {

        @Test
        @DisplayName("Provider reports FIPS mode status")
        void testProviderReportsFIPSMode() {
            GlasslessProvider gp = new GlasslessProvider();
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
                Security.removeProvider("Glassless");
                GlasslessProvider fipsProvider = new GlasslessProvider();
                Security.addProvider(fipsProvider);

                assertTrue(fipsProvider.isFIPSMode(), "Provider should be in FIPS mode");

                // MD5 should not be available
                assertThrows(NoSuchAlgorithmException.class, () ->
                    MessageDigest.getInstance("MD5", "Glassless"));
            } finally {
                // Restore
                if (original != null) {
                    System.setProperty("glassless.fips.mode", original);
                } else {
                    System.clearProperty("glassless.fips.mode");
                }
                FIPSStatus.clearCache();

                // Restore original provider
                Security.removeProvider("Glassless");
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

                Security.removeProvider("Glassless");
                GlasslessProvider fipsProvider = new GlasslessProvider();
                Security.addProvider(fipsProvider);

                assertThrows(NoSuchAlgorithmException.class, () ->
                    Cipher.getInstance("ChaCha20-Poly1305", "Glassless"));
            } finally {
                if (original != null) {
                    System.setProperty("glassless.fips.mode", original);
                } else {
                    System.clearProperty("glassless.fips.mode");
                }
                FIPSStatus.clearCache();
                Security.removeProvider("Glassless");
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

                Security.removeProvider("Glassless");
                GlasslessProvider fipsProvider = new GlasslessProvider();
                Security.addProvider(fipsProvider);

                assertThrows(NoSuchAlgorithmException.class, () ->
                    SecretKeyFactory.getInstance("SCRYPT", "Glassless"));
            } finally {
                if (original != null) {
                    System.setProperty("glassless.fips.mode", original);
                } else {
                    System.clearProperty("glassless.fips.mode");
                }
                FIPSStatus.clearCache();
                Security.removeProvider("Glassless");
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

                Security.removeProvider("Glassless");
                GlasslessProvider fipsProvider = new GlasslessProvider();
                Security.addProvider(fipsProvider);

                // SHA-256 should still be available
                MessageDigest md = MessageDigest.getInstance("SHA-256", "Glassless");
                assertNotNull(md);
            } finally {
                if (original != null) {
                    System.setProperty("glassless.fips.mode", original);
                } else {
                    System.clearProperty("glassless.fips.mode");
                }
                FIPSStatus.clearCache();
                Security.removeProvider("Glassless");
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

                Security.removeProvider("Glassless");
                GlasslessProvider fipsProvider = new GlasslessProvider();
                Security.addProvider(fipsProvider);

                // AES-GCM should still be available
                Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "Glassless");
                assertNotNull(cipher);
            } finally {
                if (original != null) {
                    System.setProperty("glassless.fips.mode", original);
                } else {
                    System.clearProperty("glassless.fips.mode");
                }
                FIPSStatus.clearCache();
                Security.removeProvider("Glassless");
                Security.addProvider(provider);
            }
        }
    }
}
