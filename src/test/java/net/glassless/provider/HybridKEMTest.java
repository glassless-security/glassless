package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Tests for hybrid KEM algorithms.
 * These combine classical key agreement with ML-KEM for quantum-resistant key encapsulation.
 */
class HybridKEMTest {

   @BeforeAll
   static void setup() {
      Security.addProvider(new GlaSSLessProvider());
   }

   @Nested
   @DisplayName("X25519MLKEM768 Tests")
   class X25519MLKEM768Tests {

      @Test
      @DisplayName("Should generate key pair")
      void shouldGenerateKeyPair() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KeyPair keyPair = kpg.generateKeyPair();

         assertNotNull(keyPair);
         assertNotNull(keyPair.getPublic());
         assertNotNull(keyPair.getPrivate());
         assertEquals("X25519MLKEM768", keyPair.getPublic().getAlgorithm());
         assertEquals("X25519MLKEM768", keyPair.getPrivate().getAlgorithm());
      }

      @Test
      @DisplayName("Should encapsulate and decapsulate")
      void shouldEncapsulateAndDecapsulate() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         // Generate key pair
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KeyPair keyPair = kpg.generateKeyPair();

         // Get KEM instance
         KEM kem = KEM.getInstance("X25519MLKEM768", "GlaSSLess");

         // Encapsulate with public key
         KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
         KEM.Encapsulated encapsulated = encapsulator.encapsulate();

         assertNotNull(encapsulated.key());
         assertNotNull(encapsulated.encapsulation());
         assertEquals(64, encapsulated.key().getEncoded().length, "Hybrid KEM shared secret should be 64 bytes");
         assertEquals(1120, encapsulated.encapsulation().length, "X25519MLKEM768 ciphertext should be 1120 bytes");

         // Decapsulate with private key
         KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());
         SecretKey decapsulatedKey = decapsulator.decapsulate(encapsulated.encapsulation());

         assertNotNull(decapsulatedKey);
         assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded(),
            "Encapsulated and decapsulated keys should match");
      }

      @Test
      @DisplayName("Should support partial key extraction")
      void shouldSupportPartialKeyExtraction() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KeyPair keyPair = kpg.generateKeyPair();

         KEM kem = KEM.getInstance("X25519MLKEM768", "GlaSSLess");
         KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());

         // Extract only first 32 bytes for AES-256
         KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
         assertEquals(32, encapsulated.key().getEncoded().length);
         assertEquals("AES", encapsulated.key().getAlgorithm());
      }
   }

   @Nested
   @DisplayName("X448MLKEM1024 Tests")
   class X448MLKEM1024Tests {

      @Test
      @DisplayName("Should generate key pair and perform encapsulation")
      void shouldGenerateAndEncapsulate() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X448MLKEM1024"),
            "X448MLKEM1024 requires OpenSSL 3.5+");

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X448MLKEM1024", "GlaSSLess");
         KeyPair keyPair = kpg.generateKeyPair();

         KEM kem = KEM.getInstance("X448MLKEM1024", "GlaSSLess");
         KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
         KEM.Encapsulated encapsulated = encapsulator.encapsulate();

         assertNotNull(encapsulated.key());
         assertEquals(64, encapsulated.key().getEncoded().length);

         KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());
         SecretKey decapsulatedKey = decapsulator.decapsulate(encapsulated.encapsulation());

         assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
      }
   }

   // Note: EC-based hybrid KEMs (SecP256r1MLKEM768, SecP384r1MLKEM1024) are not currently
   // supported because OpenSSL 3.5 doesn't provide raw key export for these types.

   @Nested
   @DisplayName("Hybrid KEM Generic Tests")
   class GenericTests {

      @Test
      @DisplayName("Should reject invalid encapsulation data")
      void shouldRejectInvalidEncapsulation() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KeyPair keyPair = kpg.generateKeyPair();

         KEM kem = KEM.getInstance("X25519MLKEM768", "GlaSSLess");
         KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());

         // Try to decapsulate invalid data
         byte[] invalidData = new byte[1120];
         assertThrows(Exception.class, () -> decapsulator.decapsulate(invalidData));
      }

      @Test
      @DisplayName("Should report correct sizes")
      void shouldReportCorrectSizes() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KeyPair keyPair = kpg.generateKeyPair();

         KEM kem = KEM.getInstance("X25519MLKEM768", "GlaSSLess");
         KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());

         assertEquals(64, encapsulator.secretSize());
         assertEquals(1120, encapsulator.encapsulationSize());
      }
   }
}
