package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class PBECipherTest {

    private static final String PASSWORD = "testPassword123!";
    private static final int ITERATION_COUNT = 10000;

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    private byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] generateIv(int length) {
        byte[] iv = new byte[length];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    @Nested
    @DisplayName("PBE with HMAC SHA variants and AES")
    class PBEWithHmacSHAAndAESTests {

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
        void testPBECipher(String hashAlgorithm, int keySize) throws Exception {
            String algorithm = String.format("PBEWithHmac%sAndAES_%d", hashAlgorithm, keySize);

            // Get cipher from our provider
            Cipher cipher = Cipher.getInstance(algorithm, "GlaSSLess");
            assertNotNull(cipher);

            // Create PBE key
            PBEKeySpec keySpec = new PBEKeySpec(PASSWORD.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBE");
            SecretKey pbeKey = keyFactory.generateSecret(keySpec);

            // Generate salt and IV
            byte[] salt = generateSalt(16);
            byte[] iv = generateIv(16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            PBEParameterSpec pbeParams = new PBEParameterSpec(salt, ITERATION_COUNT, ivSpec);

            // Test data
            byte[] plaintext = "This is a test message for PBE encryption!".getBytes();

            // Encrypt
            cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParams);
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decrypt - need a new cipher instance since we freed the context
            Cipher decryptCipher = Cipher.getInstance(algorithm, "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParams);
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes, "Decrypted text mismatch for " + algorithm);
        }

        @ParameterizedTest(name = "PBEWithHmac{0}AndAES_{1} - Various plaintext sizes")
        @CsvSource({
                "SHA256, 128, 1",
                "SHA256, 128, 15",
                "SHA256, 128, 16",
                "SHA256, 128, 17",
                "SHA256, 128, 32",
                "SHA256, 128, 100",
                "SHA256, 256, 1",
                "SHA256, 256, 15",
                "SHA256, 256, 16",
                "SHA256, 256, 17",
                "SHA256, 256, 32",
                "SHA256, 256, 100"
        })
        void testPBECipherVariousPlaintextSizes(String hashAlgorithm, int keySize, int plaintextSize) throws Exception {
            String algorithm = String.format("PBEWithHmac%sAndAES_%d", hashAlgorithm, keySize);

            // Get cipher from our provider
            Cipher cipher = Cipher.getInstance(algorithm, "GlaSSLess");

            // Create PBE key
            PBEKeySpec keySpec = new PBEKeySpec(PASSWORD.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBE");
            SecretKey pbeKey = keyFactory.generateSecret(keySpec);

            // Generate salt and IV
            byte[] salt = generateSalt(16);
            byte[] iv = generateIv(16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            PBEParameterSpec pbeParams = new PBEParameterSpec(salt, ITERATION_COUNT, ivSpec);

            // Generate plaintext of specified size
            byte[] plaintext = new byte[plaintextSize];
            new SecureRandom().nextBytes(plaintext);

            // Encrypt
            cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParams);
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decrypt
            Cipher decryptCipher = Cipher.getInstance(algorithm, "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParams);
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes,
                "Decrypted text mismatch for " + algorithm + " with plaintext size " + plaintextSize);
        }
    }
}
