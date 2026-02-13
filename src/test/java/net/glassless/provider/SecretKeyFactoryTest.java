package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

public class SecretKeyFactoryTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlasslessProvider());
    }

    private byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    @Nested
    @DisplayName("PBKDF2 SecretKeyFactory")
    class PBKDF2Tests {

        @ParameterizedTest(name = "PBKDF2WithHmac{0}")
        @CsvSource({
                "SHA1, 20",
                "SHA224, 28",
                "SHA256, 32",
                "SHA384, 48",
                "SHA512, 64"
        })
        void testPBKDF2KeyDerivation(String hashAlgorithm, int expectedKeyLength) throws Exception {
            String algorithm = "PBKDF2WithHmac" + hashAlgorithm;
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, "Glassless");
            assertNotNull(factory);

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, expectedKeyLength * 8);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(expectedKeyLength, key.getEncoded().length);
        }

        @Test
        @DisplayName("PBKDF2 produces consistent keys")
        void testPBKDF2Consistency() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "Glassless");

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec1 = new PBEKeySpec(password, salt, iterationCount, 256);
            SecretKey key1 = factory.generateSecret(keySpec1);

            PBEKeySpec keySpec2 = new PBEKeySpec(password, salt, iterationCount, 256);
            SecretKey key2 = factory.generateSecret(keySpec2);

            assertArrayEquals(key1.getEncoded(), key2.getEncoded());
        }

        @Test
        @DisplayName("PBKDF2 different passwords produce different keys")
        void testPBKDF2DifferentPasswords() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "Glassless");

            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec1 = new PBEKeySpec("password1".toCharArray(), salt, iterationCount, 256);
            SecretKey key1 = factory.generateSecret(keySpec1);

            PBEKeySpec keySpec2 = new PBEKeySpec("password2".toCharArray(), salt, iterationCount, 256);
            SecretKey key2 = factory.generateSecret(keySpec2);

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
            assertTrue(different, "Different passwords should produce different keys");
        }

        @ParameterizedTest(name = "PBKDF2WithHmac{0}And8BIT")
        @CsvSource({
                "SHA1, 20",
                "SHA224, 28",
                "SHA256, 32",
                "SHA384, 48",
                "SHA512, 64"
        })
        void testPBKDF2With8BitEncoding(String hashAlgorithm, int expectedKeyLength) throws Exception {
            String algorithm = "PBKDF2WithHmac" + hashAlgorithm + "And8BIT";
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, "Glassless");
            assertNotNull(factory);

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, expectedKeyLength * 8);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(expectedKeyLength, key.getEncoded().length);
        }

        @ParameterizedTest(name = "PBKDF2WithHmacSHA3-{0}")
        @CsvSource({
                "224, 28",
                "256, 32",
                "384, 48",
                "512, 64"
        })
        void testPBKDF2WithSHA3(String sha3Variant, int expectedKeyLength) throws Exception {
            String algorithm = "PBKDF2WithHmacSHA3-" + sha3Variant;
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, "Glassless");
            assertNotNull(factory);

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, expectedKeyLength * 8);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(expectedKeyLength, key.getEncoded().length);
        }

        @Test
        @DisplayName("8BIT encoding differs from UTF-8 for high-byte chars")
        void testEncodingDifference() throws Exception {
            SecretKeyFactory utf8Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "Glassless");
            SecretKeyFactory eightBitFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256And8BIT", "Glassless");

            // Use a password with characters that encode differently in UTF-8 vs 8-bit
            char[] password = new char[] { '\u00E9', '\u00FC', '\u00F1' }; // é, ü, ñ
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec1 = new PBEKeySpec(password, salt, iterationCount, 256);
            SecretKey utf8Key = utf8Factory.generateSecret(keySpec1);

            PBEKeySpec keySpec2 = new PBEKeySpec(password, salt, iterationCount, 256);
            SecretKey eightBitKey = eightBitFactory.generateSecret(keySpec2);

            // Keys should be different because encoding is different
            byte[] k1 = utf8Key.getEncoded();
            byte[] k2 = eightBitKey.getEncoded();
            boolean different = false;
            for (int i = 0; i < k1.length; i++) {
                if (k1[i] != k2[i]) {
                    different = true;
                    break;
                }
            }
            assertTrue(different, "UTF-8 and 8-bit encodings should produce different keys for non-ASCII chars");
        }

        @Test
        @DisplayName("PBKDF2 derived key can be used for AES encryption")
        void testPBKDF2KeyForEncryption() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "Glassless");

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            // Derive a 256-bit key for AES
            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, 256);
            SecretKey derivedKey = factory.generateSecret(keySpec);

            // Create AES key from derived bytes
            SecretKey aesKey = new SecretKeySpec(derivedKey.getEncoded(), "AES");

            // Use for AES encryption
            Cipher cipher = Cipher.getInstance("AES_256/CBC/PKCS5Padding", "Glassless");
            byte[] iv = generateSalt(16);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

            byte[] plaintext = "Test message for PBKDF2 derived key".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Nested
    @DisplayName("PBE SecretKeyFactory")
    class PBETests {

        @Test
        @DisplayName("PBE key generation from password")
        void testPBEKeyGeneration() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE", "Glassless");
            assertNotNull(factory);

            char[] password = "testPassword123!".toCharArray();
            PBEKeySpec keySpec = new PBEKeySpec(password);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals("PBE", key.getAlgorithm());
        }
    }

    @Nested
    @DisplayName("DESede SecretKeyFactory")
    class DESedeTests {

        @Test
        @DisplayName("DESede key from DESedeKeySpec")
        void testDESedeFromKeySpec() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede", "Glassless");
            assertNotNull(factory);

            // Generate 24-byte key material
            byte[] keyBytes = new byte[24];
            new SecureRandom().nextBytes(keyBytes);

            DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals("DESede", key.getAlgorithm());
            assertEquals(24, key.getEncoded().length);
        }

        @Test
        @DisplayName("DESede key has correct parity bits")
        void testDESedeParityBits() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede", "Glassless");

            byte[] keyBytes = new byte[24];
            new SecureRandom().nextBytes(keyBytes);

            DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
            SecretKey key = factory.generateSecret(keySpec);

            // Each byte should have odd parity
            for (byte b : key.getEncoded()) {
                int bitCount = Integer.bitCount(b & 0xFF);
                assertEquals(1, bitCount % 2, "Each byte should have odd parity");
            }
        }

        @Test
        @DisplayName("TripleDES alias works")
        void testTripleDESAlias() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("TripleDES", "Glassless");
            assertNotNull(factory);

            byte[] keyBytes = new byte[24];
            new SecureRandom().nextBytes(keyBytes);

            DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
        }
    }

    @Nested
    @DisplayName("PBES2 SecretKeyFactory")
    class PBES2Tests {

        @ParameterizedTest(name = "PBEWithHmac{0}AndAES_{1}")
        @CsvSource({
                "SHA1, 128",
                "SHA1, 256",
                "SHA224, 128",
                "SHA224, 256",
                "SHA256, 128",
                "SHA256, 256",
                "SHA384, 128",
                "SHA384, 256",
                "SHA512, 128",
                "SHA512, 256"
        })
        void testPBES2KeyDerivation(String hashAlgorithm, int keySize) throws Exception {
            String algorithm = "PBEWithHmac" + hashAlgorithm + "AndAES_" + keySize;
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, "Glassless");
            assertNotNull(factory);

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(keySize / 8, key.getEncoded().length);
        }

        @ParameterizedTest(name = "PBEWithHmacSHA512/{0}AndAES_{1}")
        @CsvSource({
                "224, 128",
                "224, 256",
                "256, 128",
                "256, 256"
        })
        void testPBES2WithSHA512Truncated(String truncation, int keySize) throws Exception {
            String algorithm = "PBEWithHmacSHA512/" + truncation + "AndAES_" + keySize;
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, "Glassless");
            assertNotNull(factory);

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount);
            SecretKey key = factory.generateSecret(keySpec);

            assertNotNull(key);
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(keySize / 8, key.getEncoded().length);
        }

        @Test
        @DisplayName("PBES2 produces consistent keys")
        void testPBES2Consistency() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256", "Glassless");

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec1 = new PBEKeySpec(password, salt, iterationCount);
            SecretKey key1 = factory.generateSecret(keySpec1);

            PBEKeySpec keySpec2 = new PBEKeySpec(password, salt, iterationCount);
            SecretKey key2 = factory.generateSecret(keySpec2);

            assertArrayEquals(key1.getEncoded(), key2.getEncoded());
        }

        @Test
        @DisplayName("PBES2 derived key can be used for AES encryption")
        void testPBES2KeyForEncryption() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256", "Glassless");

            char[] password = "testPassword123!".toCharArray();
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;

            PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount);
            SecretKey derivedKey = factory.generateSecret(keySpec);

            // Create AES key from derived bytes
            SecretKey aesKey = new SecretKeySpec(derivedKey.getEncoded(), "AES");

            // Use for AES encryption
            Cipher cipher = Cipher.getInstance("AES_256/CBC/PKCS5Padding", "Glassless");
            byte[] iv = generateSalt(16);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

            byte[] plaintext = "Test message for PBES2 derived key".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Nested
    @DisplayName("AES SecretKeyFactory")
    class AESTests {

        @ParameterizedTest(name = "AES with {0}-byte key")
        @ValueSource(ints = {16, 24, 32})
        void testAESFromSecretKeySpec(int keyLength) throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", "Glassless");
            assertNotNull(factory);

            byte[] keyBytes = new byte[keyLength];
            new SecureRandom().nextBytes(keyBytes);

            SecretKeySpec inputSpec = new SecretKeySpec(keyBytes, "AES");
            SecretKey key = factory.generateSecret(inputSpec);

            assertNotNull(key);
            assertEquals("AES", key.getAlgorithm());
            assertEquals(keyLength, key.getEncoded().length);
            assertArrayEquals(keyBytes, key.getEncoded());
        }

        @Test
        @DisplayName("AES key translation")
        void testAESKeyTranslation() throws Exception {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", "Glassless");

            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);

            SecretKeySpec originalKey = new SecretKeySpec(keyBytes, "AES");
            SecretKey translatedKey = factory.translateKey(originalKey);

            assertNotNull(translatedKey);
            assertEquals("AES", translatedKey.getAlgorithm());
            assertArrayEquals(keyBytes, translatedKey.getEncoded());
        }
    }
}
