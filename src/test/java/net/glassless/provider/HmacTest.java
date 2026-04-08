package net.glassless.provider;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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
            Mac mac = Mac.getInstance(macAlgorithm, PROVIDER_NAME);
            assertNotNull(mac);

            byte[] keyBytes = generateKey(keyLength);
            SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);

            mac.init(key);
            assertEquals(expectedMacLength, mac.getMacLength());

            byte[] data = "Test data for HMAC".getBytes(StandardCharsets.UTF_8);
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
            Mac mac = Mac.getInstance(macAlgorithm, PROVIDER_NAME);

            byte[] keyBytes = generateKey(32);
            SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);

            mac.init(key);

            // Update incrementally
            mac.update("Part 1 ".getBytes(StandardCharsets.UTF_8));
            mac.update("Part 2 ".getBytes(StandardCharsets.UTF_8));
            mac.update("Part 3".getBytes(StandardCharsets.UTF_8));
            byte[] result1 = mac.doFinal();

            // Compare with single update
            mac.init(key);
            byte[] result2 = mac.doFinal("Part 1 Part 2 Part 3".getBytes(StandardCharsets.UTF_8));

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
            Mac mac = Mac.getInstance(macAlgorithm, PROVIDER_NAME);
            assertNotNull(mac);

            byte[] keyBytes = generateKey(32);
            SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);

            mac.init(key);
            assertEquals(expectedMacLength, mac.getMacLength());

            byte[] data = "Test data for HMAC SHA3".getBytes(StandardCharsets.UTF_8);
            byte[] result = mac.doFinal(data);

            assertNotNull(result);
            assertEquals(expectedMacLength, result.length);
        }
    }

    // HmacPBE algorithms (HmacPBESHA1, HmacPBESHA256, etc.) use the PKCS#12 KDF
    // (RFC 7292 Appendix B), not PBKDF2. These are left to SunJCE which implements
    // the correct KDF.
}
