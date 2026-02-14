package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class HmacTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    private byte[] generateKey(int length) {
        byte[] key = new byte[length];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    @Nested
    @DisplayName("HMAC with SHA variants")
    class HmacSHATests {

        @ParameterizedTest(name = "Hmac{0} with {1} byte key")
        @CsvSource({
                "SHA1, 20, 20",
                "SHA1, 32, 20",
                "SHA1, 64, 20",
                "SHA224, 28, 28",
                "SHA224, 32, 28",
                "SHA256, 32, 32",
                "SHA256, 64, 32",
                "SHA384, 48, 48",
                "SHA384, 64, 48",
                "SHA512, 64, 64",
                "SHA512, 128, 64"
        })
        void testHmacSHA(String algorithm, int keyLength, int expectedMacLength) throws Exception {
            String macAlgorithm = "Hmac" + algorithm;
            Mac mac = Mac.getInstance(macAlgorithm, "GlaSSLess");
            assertNotNull(mac);

            byte[] keyBytes = generateKey(keyLength);
            SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);

            mac.init(key);
            assertEquals(expectedMacLength, mac.getMacLength());

            byte[] data = "Test data for HMAC".getBytes();
            byte[] result = mac.doFinal(data);

            assertNotNull(result);
            assertEquals(expectedMacLength, result.length);

            // Verify consistency - same input should produce same output
            mac.init(key);
            byte[] result2 = mac.doFinal(data);
            assertArrayEquals(result, result2);
        }

        @ParameterizedTest(name = "Hmac{0} incremental update")
        @CsvSource({
                "SHA1, 20",
                "SHA256, 32",
                "SHA512, 64"
        })
        void testHmacIncrementalUpdate(String algorithm, int expectedMacLength) throws Exception {
            String macAlgorithm = "Hmac" + algorithm;
            Mac mac = Mac.getInstance(macAlgorithm, "GlaSSLess");

            byte[] keyBytes = generateKey(32);
            SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);

            mac.init(key);

            // Update incrementally
            mac.update("Part 1 ".getBytes());
            mac.update("Part 2 ".getBytes());
            mac.update("Part 3".getBytes());
            byte[] result1 = mac.doFinal();

            // Compare with single update
            mac.init(key);
            byte[] result2 = mac.doFinal("Part 1 Part 2 Part 3".getBytes());

            assertArrayEquals(result1, result2);
        }
    }

    @Nested
    @DisplayName("HMAC with SHA3 variants")
    class HmacSHA3Tests {

        @ParameterizedTest(name = "HmacSHA3-{0}")
        @CsvSource({
                "224, 28",
                "256, 32",
                "384, 48",
                "512, 64"
        })
        void testHmacSHA3(int bits, int expectedMacLength) throws Exception {
            String macAlgorithm = "HmacSHA3-" + bits;
            Mac mac = Mac.getInstance(macAlgorithm, "GlaSSLess");
            assertNotNull(mac);

            byte[] keyBytes = generateKey(32);
            SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);

            mac.init(key);
            assertEquals(expectedMacLength, mac.getMacLength());

            byte[] data = "Test data for HMAC SHA3".getBytes();
            byte[] result = mac.doFinal(data);

            assertNotNull(result);
            assertEquals(expectedMacLength, result.length);
        }
    }

    @Nested
    @DisplayName("HmacPBE variants")
    class HmacPBETests {

        @ParameterizedTest(name = "HmacPBE{0}")
        @CsvSource({
                "SHA1, 20",
                "SHA224, 28",
                "SHA256, 32",
                "SHA384, 48",
                "SHA512, 64"
        })
        void testHmacPBE(String algorithm, int expectedMacLength) throws Exception {
            String macAlgorithm = "HmacPBE" + algorithm;
            Mac mac = Mac.getInstance(macAlgorithm, "GlaSSLess");
            assertNotNull(mac);

            // Create PBE key
            String password = "testPassword123!";
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBE");
            SecretKey pbeKey = keyFactory.generateSecret(keySpec);

            // Create PBE params
            byte[] salt = generateSalt(16);
            int iterationCount = 10000;
            PBEParameterSpec pbeParams = new PBEParameterSpec(salt, iterationCount);

            mac.init(pbeKey, pbeParams);
            assertEquals(expectedMacLength, mac.getMacLength());

            byte[] data = "Test data for PBE HMAC".getBytes();
            byte[] result = mac.doFinal(data);

            assertNotNull(result);
            assertEquals(expectedMacLength, result.length);

            // Verify consistency with same password, salt, and iteration count
            Mac mac2 = Mac.getInstance(macAlgorithm, "GlaSSLess");
            mac2.init(pbeKey, pbeParams);
            byte[] result2 = mac2.doFinal(data);
            assertArrayEquals(result, result2);
        }

        @Test
        @DisplayName("HmacPBESHA256 with different salts produces different results")
        void testHmacPBEDifferentSalts() throws Exception {
            String macAlgorithm = "HmacPBESHA256";
            String password = "testPassword123!";
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBE");
            SecretKey pbeKey = keyFactory.generateSecret(keySpec);

            byte[] salt1 = generateSalt(16);
            byte[] salt2 = generateSalt(16);
            int iterationCount = 10000;

            byte[] data = "Test data".getBytes();

            Mac mac1 = Mac.getInstance(macAlgorithm, "GlaSSLess");
            mac1.init(pbeKey, new PBEParameterSpec(salt1, iterationCount));
            byte[] result1 = mac1.doFinal(data);

            Mac mac2 = Mac.getInstance(macAlgorithm, "GlaSSLess");
            mac2.init(pbeKey, new PBEParameterSpec(salt2, iterationCount));
            byte[] result2 = mac2.doFinal(data);

            // Different salts should produce different results
            boolean different = false;
            for (int i = 0; i < result1.length; i++) {
                if (result1[i] != result2[i]) {
                    different = true;
                    break;
                }
            }
            assertEquals(true, different, "Different salts should produce different MAC values");
        }
    }
}
