package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class DESedeCipherTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlasslessProvider());
    }

    private SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(168); // DESede uses 168-bit keys (actually 192 bits with parity)
        return keyGen.generateKey();
    }

    private byte[] generateIv() {
        // DESede uses 8-byte IV (64-bit block size)
        byte[] iv = new byte[8];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }

    // Helper to get plaintext that is a multiple of block size (8 bytes for DESede)
    private byte[] getBlockAlignedPlaintext(int blocks) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < blocks; i++) {
            sb.append("12345678"); // 8 bytes per block
        }
        return sb.toString().getBytes();
    }

    @Nested
    @DisplayName("DESede NoPadding Ciphers")
    class DESedeNoPaddingTests {

        @ParameterizedTest(name = "{0} mode")
        @CsvSource({
                "ECB",
                "CBC"
        })
        void testDESedeNoPadding(String mode) throws Exception {
            String algorithm = String.format("DESede/%s/NoPadding", mode);
            Cipher cipher = Cipher.getInstance(algorithm, "Glassless");
            SecretKey secretKey = generateKey();

            byte[] iv = null;
            if (!mode.equals("ECB")) {
                iv = generateIv();
            }

            // Plaintext must be a multiple of block size for NoPadding (DESede block size = 8)
            byte[] plaintext = getBlockAlignedPlaintext(4); // 4 blocks = 32 bytes

            // Encryption
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decryption
            Cipher decryptCipher = Cipher.getInstance(algorithm, "Glassless");
            if (iv == null) {
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
            } else {
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes, "Decrypted text mismatch for " + algorithm);
        }
    }

    @Nested
    @DisplayName("DESede PKCS5Padding Ciphers")
    class DESedePKCS5PaddingTests {

        @ParameterizedTest(name = "{0} mode")
        @CsvSource({
                "ECB",
                "CBC"
        })
        void testDESedePKCS5Padding(String mode) throws Exception {
            String algorithm = String.format("DESede/%s/PKCS5Padding", mode);
            Cipher cipher = Cipher.getInstance(algorithm, "Glassless");
            SecretKey secretKey = generateKey();

            byte[] iv = null;
            if (!mode.equals("ECB")) {
                iv = generateIv();
            }

            // Plaintext can be any length for PKCS5Padding
            byte[] plaintext = "A short plaintext for testing DESede padding".getBytes();

            // Encryption
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Expected length: next multiple of 8
            int expectedLength = ((plaintext.length / 8) + 1) * 8;
            assertEquals(expectedLength, encryptedBytes.length, "Encrypted length mismatch for " + algorithm);

            // Decryption
            Cipher decryptCipher = Cipher.getInstance(algorithm, "Glassless");
            if (iv == null) {
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
            } else {
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes, "Decrypted text mismatch for " + algorithm);
        }

        @ParameterizedTest(name = "{0} mode with {1} byte plaintext")
        @CsvSource({
                "CBC, 1",
                "CBC, 7",
                "CBC, 8",
                "CBC, 9",
                "CBC, 16",
                "CBC, 100"
        })
        void testDESedePKCS5PaddingVariousSizes(String mode, int plaintextSize) throws Exception {
            String algorithm = String.format("DESede/%s/PKCS5Padding", mode);
            Cipher cipher = Cipher.getInstance(algorithm, "Glassless");
            SecretKey secretKey = generateKey();

            byte[] iv = generateIv();

            // Generate plaintext of specified size
            byte[] plaintext = new byte[plaintextSize];
            new java.security.SecureRandom().nextBytes(plaintext);

            // Encryption
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decryption
            Cipher decryptCipher = Cipher.getInstance(algorithm, "Glassless");
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes,
                "Decrypted text mismatch for " + algorithm + " with plaintext size " + plaintextSize);
        }
    }
}
