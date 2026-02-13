package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class RSACipherTest {

    private static KeyPair keyPair2048;
    private static KeyPair keyPair4096;

    @BeforeAll
    public static void setUp() throws Exception {
        Security.addProvider(new GlasslessProvider());

        // Generate RSA key pairs for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair2048 = keyGen.generateKeyPair();

        keyGen.initialize(4096);
        keyPair4096 = keyGen.generateKeyPair();
    }

    @Nested
    @DisplayName("RSA PKCS1Padding")
    class RSAPKCS1PaddingTests {

        @ParameterizedTest(name = "{0}-bit key, plaintext size {1}")
        @CsvSource({
                "2048, 1",
                "2048, 10",
                "2048, 100",
                "2048, 200",  // Max for 2048-bit key with PKCS1 is 245 bytes
                "4096, 1",
                "4096, 100",
                "4096, 400"   // Max for 4096-bit key with PKCS1 is 501 bytes
        })
        void testRSAPKCS1Padding(int keySize, int plaintextSize) throws Exception {
            KeyPair keyPair = keySize == 2048 ? keyPair2048 : keyPair4096;

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "Glassless");

            // Generate plaintext
            byte[] plaintext = new byte[plaintextSize];
            new java.security.SecureRandom().nextBytes(plaintext);

            // Encrypt with public key
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decrypt with private key
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "Glassless");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes, "Decrypted text mismatch");
        }

        @Test
        @DisplayName("RSA alias test")
        void testRSAAlias() throws Exception {
            // Test that "RSA" alias works
            Cipher cipher = Cipher.getInstance("RSA", "Glassless");
            assertNotNull(cipher);

            byte[] plaintext = "Test message".getBytes();

            cipher.init(Cipher.ENCRYPT_MODE, keyPair2048.getPublic());
            byte[] encrypted = cipher.doFinal(plaintext);

            Cipher decryptCipher = Cipher.getInstance("RSA", "Glassless");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair2048.getPrivate());
            byte[] decrypted = decryptCipher.doFinal(encrypted);

            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Nested
    @DisplayName("RSA OAEP Padding")
    class RSAOAEPPaddingTests {

        @ParameterizedTest(name = "OAEP with {0}, {1}-bit key, plaintext size {2}")
        @CsvSource({
                "SHA-1, 2048, 1",
                "SHA-1, 2048, 50",
                "SHA-1, 2048, 100",
                "SHA-1, 4096, 100",
                "SHA-256, 2048, 1",
                "SHA-256, 2048, 50",
                "SHA-256, 2048, 100",
                "SHA-256, 4096, 100"
        })
        void testRSAOAEPPadding(String hash, int keySize, int plaintextSize) throws Exception {
            KeyPair keyPair = keySize == 2048 ? keyPair2048 : keyPair4096;
            String algorithm = String.format("RSA/ECB/OAEPWith%sAndMGF1Padding", hash);

            Cipher cipher = Cipher.getInstance(algorithm, "Glassless");

            // Generate plaintext
            byte[] plaintext = new byte[plaintextSize];
            new java.security.SecureRandom().nextBytes(plaintext);

            // Encrypt with public key
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decrypt with private key
            Cipher decryptCipher = Cipher.getInstance(algorithm, "Glassless");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes, "Decrypted text mismatch for " + algorithm);
        }
    }

    @Nested
    @DisplayName("RSA NoPadding")
    class RSANoPaddingTests {

        @Test
        @DisplayName("RSA/ECB/NoPadding with block-sized data")
        void testRSANoPadding() throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding", "Glassless");

            // For NoPadding, plaintext must be exactly key size (256 bytes for 2048-bit key)
            // and the value must be less than the modulus
            // We'll use a simple test with leading zeros
            byte[] plaintext = new byte[256]; // 2048 bits = 256 bytes
            // Fill with small values to ensure it's less than modulus
            plaintext[255] = 0x42;
            plaintext[254] = 0x43;

            // Encrypt with public key
            cipher.init(Cipher.ENCRYPT_MODE, keyPair2048.getPublic());
            byte[] encryptedBytes = cipher.doFinal(plaintext);
            assertNotNull(encryptedBytes);

            // Decrypt with private key
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NoPadding", "Glassless");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair2048.getPrivate());
            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

            assertArrayEquals(plaintext, decryptedBytes, "Decrypted text mismatch");
        }
    }
}
