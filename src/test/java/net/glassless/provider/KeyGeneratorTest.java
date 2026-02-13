package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

public class KeyGeneratorTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlasslessProvider());
    }

    @Nested
    @DisplayName("AES KeyGenerator")
    class AESKeyGeneratorTests {

        @ParameterizedTest(name = "AES with {0}-bit key")
        @ValueSource(ints = {128, 192, 256})
        void testAESKeyGeneration(int keySize) throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Glassless");
            assertNotNull(keyGen);

            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();

            assertNotNull(key);
            assertEquals("AES", key.getAlgorithm());
            assertEquals(keySize / 8, key.getEncoded().length);
        }

        @Test
        @DisplayName("AES default key size should be 128 bits")
        void testAESDefaultKeySize() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Glassless");
            SecretKey key = keyGen.generateKey();

            assertNotNull(key);
            assertEquals("AES", key.getAlgorithm());
            assertEquals(16, key.getEncoded().length); // 128 bits = 16 bytes
        }

        @Test
        @DisplayName("AES should reject invalid key sizes")
        void testAESInvalidKeySize() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Glassless");
            assertThrows(Exception.class, () -> keyGen.init(64));
        }

        @Test
        @DisplayName("Generated AES keys should be unique")
        void testAESKeyUniqueness() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Glassless");
            keyGen.init(256);

            SecretKey key1 = keyGen.generateKey();
            SecretKey key2 = keyGen.generateKey();

            assertNotNull(key1);
            assertNotNull(key2);

            // Keys should be different
            boolean different = false;
            byte[] k1 = key1.getEncoded();
            byte[] k2 = key2.getEncoded();
            for (int i = 0; i < k1.length; i++) {
                if (k1[i] != k2[i]) {
                    different = true;
                    break;
                }
            }
            assertTrue(different, "Generated keys should be unique");
        }
    }

    @Nested
    @DisplayName("DESede KeyGenerator")
    class DESedeKeyGeneratorTests {

        @Test
        @DisplayName("DESede key generation")
        void testDESedeKeyGeneration() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede", "Glassless");
            assertNotNull(keyGen);

            SecretKey key = keyGen.generateKey();

            assertNotNull(key);
            assertEquals("DESede", key.getAlgorithm());
            assertEquals(24, key.getEncoded().length); // 192 bits = 24 bytes
        }

        @Test
        @DisplayName("DESede keys should have correct parity bits")
        void testDESedeParityBits() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede", "Glassless");
            SecretKey key = keyGen.generateKey();

            byte[] keyBytes = key.getEncoded();
            for (byte b : keyBytes) {
                // Each byte should have odd parity
                int bitCount = Integer.bitCount(b & 0xFF);
                assertEquals(1, bitCount % 2, "Each byte should have odd parity");
            }
        }

        @Test
        @DisplayName("TripleDES alias should work")
        void testTripleDESAlias() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("TripleDES", "Glassless");
            assertNotNull(keyGen);

            SecretKey key = keyGen.generateKey();
            assertNotNull(key);
            assertEquals(24, key.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("HMAC KeyGenerator with SHA variants")
    class HmacSHAKeyGeneratorTests {

        @ParameterizedTest(name = "Hmac{0} KeyGenerator")
        @CsvSource({
                "SHA1, 20",
                "SHA224, 28",
                "SHA256, 32",
                "SHA384, 48",
                "SHA512, 64"
        })
        void testHmacSHAKeyGeneration(String algorithm, int expectedKeyLength) throws Exception {
            String keyGenAlgorithm = "Hmac" + algorithm;
            KeyGenerator keyGen = KeyGenerator.getInstance(keyGenAlgorithm, "Glassless");
            assertNotNull(keyGen);

            SecretKey key = keyGen.generateKey();

            assertNotNull(key);
            assertEquals(keyGenAlgorithm, key.getAlgorithm());
            assertEquals(expectedKeyLength, key.getEncoded().length);
        }

        @Test
        @DisplayName("HmacSHA256 with custom key size")
        void testHmacSHA256CustomKeySize() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256", "Glassless");
            keyGen.init(512); // 512 bits = 64 bytes

            SecretKey key = keyGen.generateKey();

            assertNotNull(key);
            assertEquals(64, key.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("HMAC KeyGenerator with SHA3 variants")
    class HmacSHA3KeyGeneratorTests {

        @ParameterizedTest(name = "HmacSHA3-{0} KeyGenerator")
        @CsvSource({
                "224, 28",
                "256, 32",
                "384, 48",
                "512, 64"
        })
        void testHmacSHA3KeyGeneration(int bits, int expectedKeyLength) throws Exception {
            String keyGenAlgorithm = "HmacSHA3-" + bits;
            KeyGenerator keyGen = KeyGenerator.getInstance(keyGenAlgorithm, "Glassless");
            assertNotNull(keyGen);

            SecretKey key = keyGen.generateKey();

            assertNotNull(key);
            assertEquals(keyGenAlgorithm, key.getAlgorithm());
            assertEquals(expectedKeyLength, key.getEncoded().length);
        }
    }
}
