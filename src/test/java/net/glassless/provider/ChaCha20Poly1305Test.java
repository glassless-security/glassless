package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class ChaCha20Poly1305Test {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("ChaCha20-Poly1305 Basic Tests")
    class BasicTests {

        @Test
        @DisplayName("Encrypt and decrypt with ChaCha20-Poly1305")
        void testEncryptDecrypt() throws Exception {
            // Generate a 256-bit key
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            // Generate a 96-bit (12-byte) nonce
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            // Plaintext
            byte[] plaintext = "Hello, ChaCha20-Poly1305!".getBytes();

            // Encrypt
            Cipher encryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encryptCipher.doFinal(plaintext);

            // Ciphertext should be plaintext + 16 bytes tag
            assertEquals(plaintext.length + 16, ciphertext.length);

            // Decrypt
            Cipher decryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = decryptCipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted);
        }

        @Test
        @DisplayName("Different nonces produce different ciphertext")
        void testDifferentNonces() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] plaintext = "Same plaintext".getBytes();

            byte[] nonce1 = new byte[12];
            byte[] nonce2 = new byte[12];
            new SecureRandom().nextBytes(nonce1);
            new SecureRandom().nextBytes(nonce2);

            Cipher cipher1 = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            cipher1.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce1));
            byte[] ciphertext1 = cipher1.doFinal(plaintext);

            Cipher cipher2 = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            cipher2.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce2));
            byte[] ciphertext2 = cipher2.doFinal(plaintext);

            assertFalse(java.util.Arrays.equals(ciphertext1, ciphertext2),
                "Different nonces should produce different ciphertext");
        }

        @Test
        @DisplayName("Tampered ciphertext fails authentication")
        void testTamperedCiphertext() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            byte[] plaintext = "Authenticate me!".getBytes();

            Cipher encryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encryptCipher.doFinal(plaintext);

            // Tamper with the ciphertext
            ciphertext[0] ^= 0xFF;

            Cipher decryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            assertThrows(Exception.class, () -> decryptCipher.doFinal(ciphertext),
                "Tampered ciphertext should fail authentication");
        }

        @Test
        @DisplayName("Tampered tag fails authentication")
        void testTamperedTag() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            byte[] plaintext = "Authenticate me!".getBytes();

            Cipher encryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encryptCipher.doFinal(plaintext);

            // Tamper with the tag (last 16 bytes)
            ciphertext[ciphertext.length - 1] ^= 0xFF;

            Cipher decryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            assertThrows(Exception.class, () -> decryptCipher.doFinal(ciphertext),
                "Tampered tag should fail authentication");
        }

        @Test
        @DisplayName("Empty plaintext")
        void testEmptyPlaintext() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            byte[] plaintext = new byte[0];

            Cipher encryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encryptCipher.doFinal(plaintext);

            // Should be just the 16-byte tag
            assertEquals(16, ciphertext.length);

            Cipher decryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = decryptCipher.doFinal(ciphertext);

            assertEquals(0, decrypted.length);
        }

        @Test
        @DisplayName("Large plaintext")
        void testLargePlaintext() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            // 1 MB plaintext
            byte[] plaintext = new byte[1024 * 1024];
            new SecureRandom().nextBytes(plaintext);

            Cipher encryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encryptCipher.doFinal(plaintext);

            assertEquals(plaintext.length + 16, ciphertext.length);

            Cipher decryptCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = decryptCipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Nested
    @DisplayName("Cross-provider Compatibility Tests")
    class CrossProviderTests {

        @Test
        @DisplayName("GlaSSLess encrypted, SunJCE decrypted")
        void testGlaSSLessToSunJCE() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            byte[] plaintext = "Cross-provider test".getBytes();

            // Encrypt with GlaSSLess
            Cipher glasslessCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            glasslessCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = glasslessCipher.doFinal(plaintext);

            // Decrypt with default provider (SunJCE)
            Cipher sunCipher = Cipher.getInstance("ChaCha20-Poly1305");
            sunCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = sunCipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted,
                "SunJCE should decrypt GlaSSLess ciphertext correctly");
        }

        @Test
        @DisplayName("SunJCE encrypted, GlaSSLess decrypted")
        void testSunJCEToGlaSSLess() throws Exception {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);

            byte[] plaintext = "Cross-provider test".getBytes();

            // Encrypt with default provider (SunJCE)
            Cipher sunCipher = Cipher.getInstance("ChaCha20-Poly1305");
            sunCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = sunCipher.doFinal(plaintext);

            // Decrypt with GlaSSLess
            Cipher glasslessCipher = Cipher.getInstance("ChaCha20-Poly1305", "GlaSSLess");
            glasslessCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = glasslessCipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted,
                "GlaSSLess should decrypt SunJCE ciphertext correctly");
        }
    }
}
