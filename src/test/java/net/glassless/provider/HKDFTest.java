package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class HKDFTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("HKDF-SHA256 Tests")
    class HKDF_SHA256_Tests {

        @Test
        @DisplayName("Extract and Expand")
        void testExtractAndExpand() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");
            assertNotNull(kdf);
            assertEquals("HKDF-SHA256", kdf.getAlgorithm());

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();
            byte[] info = "info".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 32);

            SecretKey key = kdf.deriveKey("AES", params);
            assertNotNull(key);
            assertEquals(32, key.getEncoded().length);
            assertEquals("AES", key.getAlgorithm());
        }

        @Test
        @DisplayName("Extract Only")
        void testExtractOnly() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .extractOnly();

            SecretKey prk = kdf.deriveKey("HKDF-PRK", params);
            assertNotNull(prk);
            // SHA-256 produces 32-byte PRK
            assertEquals(32, prk.getEncoded().length);
        }

        @Test
        @DisplayName("Expand Only")
        void testExpandOnly() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");

            // Use a 32-byte PRK (SHA-256 hash length)
            byte[] prk = new byte[32];
            for (int i = 0; i < 32; i++) prk[i] = (byte) i;
            byte[] info = "info".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.expandOnly(
                new SecretKeySpec(prk, "HKDF-PRK"),
                info,
                64
            );

            SecretKey key = kdf.deriveKey("AES", params);
            assertNotNull(key);
            assertEquals(64, key.getEncoded().length);
        }

        @Test
        @DisplayName("Derive Data")
        void testDeriveData() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();
            byte[] info = "info".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 48);

            byte[] data = kdf.deriveData(params);
            assertNotNull(data);
            assertEquals(48, data.length);
        }

        @Test
        @DisplayName("Multiple IKMs")
        void testMultipleIKMs() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");

            byte[] ikm1 = "first key".getBytes();
            byte[] ikm2 = "second key".getBytes();
            byte[] salt = "salt".getBytes();
            byte[] info = "info".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm1, "HKDF"))
                .addIKM(new SecretKeySpec(ikm2, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 32);

            SecretKey key = kdf.deriveKey("AES", params);
            assertNotNull(key);
            assertEquals(32, key.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("HKDF-SHA384 Tests")
    class HKDF_SHA384_Tests {

        @Test
        @DisplayName("Extract and Expand")
        void testExtractAndExpand() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA384", "GlaSSLess");
            assertNotNull(kdf);
            assertEquals("HKDF-SHA384", kdf.getAlgorithm());

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();
            byte[] info = "info".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 48);

            SecretKey key = kdf.deriveKey("AES", params);
            assertNotNull(key);
            assertEquals(48, key.getEncoded().length);
        }

        @Test
        @DisplayName("Extract Only")
        void testExtractOnly() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA384", "GlaSSLess");

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .extractOnly();

            SecretKey prk = kdf.deriveKey("HKDF-PRK", params);
            assertNotNull(prk);
            // SHA-384 produces 48-byte PRK
            assertEquals(48, prk.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("HKDF-SHA512 Tests")
    class HKDF_SHA512_Tests {

        @Test
        @DisplayName("Extract and Expand")
        void testExtractAndExpand() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA512", "GlaSSLess");
            assertNotNull(kdf);
            assertEquals("HKDF-SHA512", kdf.getAlgorithm());

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();
            byte[] info = "info".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 64);

            SecretKey key = kdf.deriveKey("AES", params);
            assertNotNull(key);
            assertEquals(64, key.getEncoded().length);
        }

        @Test
        @DisplayName("Extract Only")
        void testExtractOnly() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA512", "GlaSSLess");

            byte[] ikm = "input key material".getBytes();
            byte[] salt = "salt".getBytes();

            HKDFParameterSpec params = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .extractOnly();

            SecretKey prk = kdf.deriveKey("HKDF-PRK", params);
            assertNotNull(prk);
            // SHA-512 produces 64-byte PRK
            assertEquals(64, prk.getEncoded().length);
        }

        @Test
        @DisplayName("Expand Only with Large Output")
        void testExpandOnlyLargeOutput() throws Exception {
            KDF kdf = KDF.getInstance("HKDF-SHA512", "GlaSSLess");

            // Use a 64-byte PRK (SHA-512 hash length)
            byte[] prk = new byte[64];
            for (int i = 0; i < 64; i++) prk[i] = (byte) i;
            byte[] info = "info".getBytes();

            // HKDF can expand up to 255 * hashLen bytes (255 * 64 = 16320 for SHA-512)
            HKDFParameterSpec params = HKDFParameterSpec.expandOnly(
                new SecretKeySpec(prk, "HKDF-PRK"),
                info,
                256
            );

            SecretKey key = kdf.deriveKey("Generic", params);
            assertNotNull(key);
            assertEquals(256, key.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("Cross-provider Compatibility Tests")
    class CrossProviderTests {

        @Test
        @DisplayName("GlaSSLess and SunJCE produce same output")
        void testCrossProviderCompatibility() throws Exception {
            byte[] ikm = "input key material for cross-provider test".getBytes();
            byte[] salt = "common salt".getBytes();
            byte[] info = "context info".getBytes();

            // GlaSSLess provider
            KDF glasslessKdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");
            HKDFParameterSpec params1 = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 32);
            byte[] glasslessOutput = glasslessKdf.deriveData(params1);

            // SunJCE provider (default)
            KDF sunKdf = KDF.getInstance("HKDF-SHA256");
            HKDFParameterSpec params2 = HKDFParameterSpec.ofExtract()
                .addIKM(new SecretKeySpec(ikm, "HKDF"))
                .addSalt(salt)
                .thenExpand(info, 32);
            byte[] sunOutput = sunKdf.deriveData(params2);

            // Both should produce the same output
            assertArrayEquals(sunOutput, glasslessOutput, "GlaSSLess and SunJCE should produce same HKDF output");
        }
    }
}
