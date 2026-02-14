package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import net.glassless.provider.internal.OpenSSLCrypto;
import net.glassless.provider.internal.secretkeyfactory.Argon2KeySpec;

/**
 * Tests for Argon2 key derivation.
 * Requires OpenSSL 3.2 or later.
 */
public class Argon2Test {

   @BeforeAll
   public static void setUp() {
      Security.addProvider(new GlaSSLessProvider());
   }

   static boolean isArgon2Available() {
      return OpenSSLCrypto.isAlgorithmAvailable("KDF", "ARGON2ID");
   }

   @Test
   @DisplayName("Argon2id key derivation")
   @EnabledIf("isArgon2Available")
   void testArgon2id() throws Exception {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("Argon2id", "GlaSSLess");
      assertNotNull(skf);

      char[] password = "test-password".toCharArray();
      byte[] salt = "0123456789abcdef".getBytes();

      Argon2KeySpec spec = new Argon2KeySpec(password, salt, 3, 65536, 4, 256);
      SecretKey key = skf.generateSecret(spec);

      assertNotNull(key);
      assertEquals("Argon2id", key.getAlgorithm());
      assertEquals(32, key.getEncoded().length);
   }

   @Test
   @DisplayName("Argon2i key derivation")
   @EnabledIf("isArgon2Available")
   void testArgon2i() throws Exception {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("Argon2i", "GlaSSLess");
      assertNotNull(skf);

      char[] password = "test-password".toCharArray();
      byte[] salt = "0123456789abcdef".getBytes();

      Argon2KeySpec spec = new Argon2KeySpec(password, salt, 3, 65536, 4, 256);
      SecretKey key = skf.generateSecret(spec);

      assertNotNull(key);
      assertEquals("Argon2i", key.getAlgorithm());
      assertEquals(32, key.getEncoded().length);
   }

   @Test
   @DisplayName("Argon2d key derivation")
   @EnabledIf("isArgon2Available")
   void testArgon2d() throws Exception {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("Argon2d", "GlaSSLess");
      assertNotNull(skf);

      char[] password = "test-password".toCharArray();
      byte[] salt = "0123456789abcdef".getBytes();

      Argon2KeySpec spec = new Argon2KeySpec(password, salt, 3, 65536, 4, 256);
      SecretKey key = skf.generateSecret(spec);

      assertNotNull(key);
      assertEquals("Argon2d", key.getAlgorithm());
      assertEquals(32, key.getEncoded().length);
   }

   @Test
   @DisplayName("Argon2id produces consistent results")
   @EnabledIf("isArgon2Available")
   void testArgon2idConsistency() throws Exception {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("Argon2id", "GlaSSLess");

      char[] password = "consistent-password".toCharArray();
      byte[] salt = "fixed-salt-value".getBytes();

      Argon2KeySpec spec1 = new Argon2KeySpec(password, salt, 2, 8192, 1, 256);
      Argon2KeySpec spec2 = new Argon2KeySpec(password, salt, 2, 8192, 1, 256);

      SecretKey key1 = skf.generateSecret(spec1);
      SecretKey key2 = skf.generateSecret(spec2);

      assertArrayEquals(key1.getEncoded(), key2.getEncoded(),
         "Same parameters should produce same key");
   }

   @Test
   @DisplayName("Different passwords produce different keys")
   @EnabledIf("isArgon2Available")
   void testDifferentPasswords() throws Exception {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("Argon2id", "GlaSSLess");

      byte[] salt = "same-salt-value!".getBytes();

      Argon2KeySpec spec1 = new Argon2KeySpec("password1".toCharArray(), salt, 2, 8192, 1, 256);
      Argon2KeySpec spec2 = new Argon2KeySpec("password2".toCharArray(), salt, 2, 8192, 1, 256);

      SecretKey key1 = skf.generateSecret(spec1);
      SecretKey key2 = skf.generateSecret(spec2);

      assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()),
         "Different passwords should produce different keys");
   }
}
