package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import net.glassless.provider.internal.secretkeyfactory.ScryptKeySpec;

public class ScryptTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("SCRYPT Basic Tests")
    class BasicTests {

        @Test
        @DisplayName("Derive key with standard parameters")
        void testDeriveKey() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            char[] password = "password".toCharArray();
            byte[] salt = "salt1234salt1234".getBytes();  // 16 bytes
            int n = 16384;  // 2^14
            int r = 8;
            int p = 1;
            int keyLength = 256;  // bits

            ScryptKeySpec spec = new ScryptKeySpec(password, salt, n, r, p, keyLength);
            SecretKey key = skf.generateSecret(spec);

            assertNotNull(key);
            assertEquals("SCRYPT", key.getAlgorithm());
            assertEquals(32, key.getEncoded().length);  // 256 bits = 32 bytes
        }

        @Test
        @DisplayName("Derive key with minimal cost for testing")
        void testDeriveKeyMinimalCost() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            char[] password = "test".toCharArray();
            byte[] salt = new byte[16];
            int n = 2;  // Minimal N (must be > 1 and power of 2)
            int r = 1;
            int p = 1;
            int keyLength = 128;

            ScryptKeySpec spec = new ScryptKeySpec(password, salt, n, r, p, keyLength);
            SecretKey key = skf.generateSecret(spec);

            assertNotNull(key);
            assertEquals(16, key.getEncoded().length);
        }

        @Test
        @DisplayName("Same parameters produce same key")
        void testDeterministic() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            char[] password = "mypassword".toCharArray();
            byte[] salt = "randomsalt123456".getBytes();
            int n = 1024;
            int r = 8;
            int p = 1;
            int keyLength = 256;

            ScryptKeySpec spec1 = new ScryptKeySpec(password, salt, n, r, p, keyLength);
            SecretKey key1 = skf.generateSecret(spec1);

            ScryptKeySpec spec2 = new ScryptKeySpec(password, salt, n, r, p, keyLength);
            SecretKey key2 = skf.generateSecret(spec2);

            assertArrayEquals(key1.getEncoded(), key2.getEncoded(),
                "Same parameters should produce same key");
        }

        @Test
        @DisplayName("Different passwords produce different keys")
        void testDifferentPasswords() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            byte[] salt = "salt1234salt1234".getBytes();
            int n = 1024;
            int r = 8;
            int p = 1;
            int keyLength = 256;

            ScryptKeySpec spec1 = new ScryptKeySpec("password1".toCharArray(), salt, n, r, p, keyLength);
            SecretKey key1 = skf.generateSecret(spec1);

            ScryptKeySpec spec2 = new ScryptKeySpec("password2".toCharArray(), salt, n, r, p, keyLength);
            SecretKey key2 = skf.generateSecret(spec2);

            assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()),
                "Different passwords should produce different keys");
        }

        @Test
        @DisplayName("Different salts produce different keys")
        void testDifferentSalts() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            char[] password = "samepassword".toCharArray();
            int n = 1024;
            int r = 8;
            int p = 1;
            int keyLength = 256;

            ScryptKeySpec spec1 = new ScryptKeySpec(password, "salt1111salt1111".getBytes(), n, r, p, keyLength);
            SecretKey key1 = skf.generateSecret(spec1);

            ScryptKeySpec spec2 = new ScryptKeySpec(password, "salt2222salt2222".getBytes(), n, r, p, keyLength);
            SecretKey key2 = skf.generateSecret(spec2);

            assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()),
                "Different salts should produce different keys");
        }

        @Test
        @DisplayName("Different N values produce different keys")
        void testDifferentCostParameter() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            char[] password = "password".toCharArray();
            byte[] salt = "salt1234salt1234".getBytes();
            int r = 8;
            int p = 1;
            int keyLength = 256;

            ScryptKeySpec spec1 = new ScryptKeySpec(password, salt, 1024, r, p, keyLength);
            SecretKey key1 = skf.generateSecret(spec1);

            ScryptKeySpec spec2 = new ScryptKeySpec(password, salt, 2048, r, p, keyLength);
            SecretKey key2 = skf.generateSecret(spec2);

            assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()),
                "Different N values should produce different keys");
        }

        @Test
        @DisplayName("Constructor with defaults (r=8, p=1)")
        void testConstructorWithDefaults() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");

            char[] password = "test".toCharArray();
            byte[] salt = "0123456789abcdef".getBytes();
            int n = 1024;
            int keyLength = 256;

            // Using constructor with defaults
            ScryptKeySpec specDefaults = new ScryptKeySpec(password, salt, n, keyLength);
            SecretKey keyDefaults = skf.generateSecret(specDefaults);

            // Using explicit r=8, p=1
            ScryptKeySpec specExplicit = new ScryptKeySpec(password, salt, n, 8, 1, keyLength);
            SecretKey keyExplicit = skf.generateSecret(specExplicit);

            assertArrayEquals(keyDefaults.getEncoded(), keyExplicit.getEncoded(),
                "Default constructor should use r=8, p=1");
        }
    }

    @Nested
    @DisplayName("ScryptKeySpec Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Null password throws exception")
        void testNullPassword() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec(null, new byte[16], 1024, 8, 1, 256));
        }

        @Test
        @DisplayName("Null salt throws exception")
        void testNullSalt() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec("password".toCharArray(), null, 1024, 8, 1, 256));
        }

        @Test
        @DisplayName("N must be power of 2")
        void testNMustBePowerOf2() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec("password".toCharArray(), new byte[16], 1000, 8, 1, 256));
        }

        @Test
        @DisplayName("N must be greater than 1")
        void testNMustBeGreaterThan1() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec("password".toCharArray(), new byte[16], 1, 8, 1, 256));
        }

        @Test
        @DisplayName("r must be at least 1")
        void testRMustBeAtLeast1() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec("password".toCharArray(), new byte[16], 1024, 0, 1, 256));
        }

        @Test
        @DisplayName("p must be at least 1")
        void testPMustBeAtLeast1() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec("password".toCharArray(), new byte[16], 1024, 8, 0, 256));
        }

        @Test
        @DisplayName("keyLength must be positive")
        void testKeyLengthMustBePositive() {
            assertThrows(IllegalArgumentException.class, () ->
                new ScryptKeySpec("password".toCharArray(), new byte[16], 1024, 8, 1, 0));
        }
    }

    @Nested
    @DisplayName("Various Key Lengths")
    class KeyLengthTests {

        @Test
        @DisplayName("128-bit key")
        void test128BitKey() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");
            ScryptKeySpec spec = new ScryptKeySpec("password".toCharArray(),
                "salt1234salt1234".getBytes(), 1024, 8, 1, 128);
            SecretKey key = skf.generateSecret(spec);
            assertEquals(16, key.getEncoded().length);
        }

        @Test
        @DisplayName("256-bit key")
        void test256BitKey() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");
            ScryptKeySpec spec = new ScryptKeySpec("password".toCharArray(),
                "salt1234salt1234".getBytes(), 1024, 8, 1, 256);
            SecretKey key = skf.generateSecret(spec);
            assertEquals(32, key.getEncoded().length);
        }

        @Test
        @DisplayName("512-bit key")
        void test512BitKey() throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", "GlaSSLess");
            ScryptKeySpec spec = new ScryptKeySpec("password".toCharArray(),
                "salt1234salt1234".getBytes(), 1024, 8, 1, 512);
            SecretKey key = skf.generateSecret(spec);
            assertEquals(64, key.getEncoded().length);
        }
    }
}
