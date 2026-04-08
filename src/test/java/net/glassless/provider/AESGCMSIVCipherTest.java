package net.glassless.provider;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Tests for AES-GCM-SIV (RFC 8452) nonce-misuse-resistant authenticated encryption.
 * AES-GCM-SIV requires OpenSSL 3.2+.
 */
public class AESGCMSIVCipherTest {

   @BeforeAll
   public static void setUp() {
      Security.addProvider(new GlaSSLessProvider());
   }

   private static void assumeGcmSivAvailable() {
      assumeTrue(!FIPSStatus.isFIPSEnabled(),
         "AES-GCM-SIV is not available in FIPS mode");
      assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("CIPHER", "aes-128-gcm-siv"),
         "AES-GCM-SIV requires OpenSSL 3.2+");
   }

   private SecretKey generateKey(int keySizeBits) throws Exception {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(keySizeBits);
      return keyGen.generateKey();
   }

   @ParameterizedTest(name = "{0} bit key")
   @DisplayName("AES-GCM-SIV encrypt/decrypt round-trip")
   @CsvSource({"128", "192", "256"})
   void testEncryptDecrypt(int keySizeBits) throws Exception {
      assumeGcmSivAvailable();

      String algorithm = String.format("AES_%d/GCM-SIV/NoPadding", keySizeBits);
      Cipher cipher = Cipher.getInstance(algorithm, PROVIDER_NAME);
      SecretKey secretKey = generateKey(keySizeBits);

      byte[] iv = new byte[12]; // GCM-SIV uses 12-byte nonce
      new SecureRandom().nextBytes(iv);

      byte[] plaintext = "AES-GCM-SIV nonce-misuse-resistant AEAD test data".getBytes(StandardCharsets.UTF_8);

      // Encrypt
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
      byte[] ciphertext = cipher.doFinal(plaintext);
      assertNotNull(ciphertext);
      // Output should be plaintext + 16-byte tag
      assertArrayEquals(new int[]{plaintext.length + 16}, new int[]{ciphertext.length},
         "Ciphertext should be plaintext length + 16 byte tag");

      // Decrypt
      cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
      byte[] decrypted = cipher.doFinal(ciphertext);
      assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
   }

   @Test
   @DisplayName("AES-GCM-SIV large plaintext")
   void testLargePlaintext() throws Exception {
      assumeGcmSivAvailable();

      Cipher cipher = Cipher.getInstance("AES_256/GCM-SIV/NoPadding", PROVIDER_NAME);
      SecretKey secretKey = generateKey(256);

      byte[] iv = new byte[12];
      new SecureRandom().nextBytes(iv);

      byte[] plaintext = new byte[8192];
      new SecureRandom().nextBytes(plaintext);

      cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
      byte[] ciphertext = cipher.doFinal(plaintext);

      cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
      byte[] decrypted = cipher.doFinal(ciphertext);
      assertArrayEquals(plaintext, decrypted);
   }

   @Test
   @DisplayName("AES-GCM-SIV tampered ciphertext fails verification")
   void testTamperedCiphertext() throws Exception {
      assumeGcmSivAvailable();

      Cipher cipher = Cipher.getInstance("AES_256/GCM-SIV/NoPadding", PROVIDER_NAME);
      SecretKey secretKey = generateKey(256);

      byte[] iv = new byte[12];
      new SecureRandom().nextBytes(iv);

      byte[] plaintext = "Authenticated data".getBytes(StandardCharsets.UTF_8);

      cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
      byte[] ciphertext = cipher.doFinal(plaintext);

      // Tamper with ciphertext
      ciphertext[0] ^= 0xFF;

      cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
      org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
         () -> cipher.doFinal(ciphertext),
         "Tampered ciphertext should fail authentication");
   }
}
