package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;

import javax.crypto.KDF;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import net.glassless.provider.internal.kdf.KBKDFParameterSpec;
import net.glassless.provider.internal.kdf.SSHKDFParameterSpec;
import net.glassless.provider.internal.kdf.TLSPRFParameterSpec;
import net.glassless.provider.internal.kdf.X963KDFParameterSpec;

/**
 * Tests for KDF implementations.
 */
public class KDFTest {

   @BeforeAll
   public static void setUp() {
      Security.addProvider(new GlasslessProvider());
   }

   @Nested
   @DisplayName("X9.63 KDF Tests")
   class X963KDFTests {

      @Test
      @DisplayName("X963KDF-SHA256 basic derivation")
      void testX963KDFSHA256() throws Exception {
         KDF kdf = KDF.getInstance("X963KDF-SHA256", "Glassless");
         assertNotNull(kdf);

         byte[] sharedSecret = new byte[32];
         for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;
         byte[] sharedInfo = "context".getBytes();

         X963KDFParameterSpec params = new X963KDFParameterSpec(sharedSecret, sharedInfo, 32);
         SecretKey key = kdf.deriveKey("AES", params);

         assertNotNull(key);
         assertEquals("AES", key.getAlgorithm());
         assertEquals(32, key.getEncoded().length);
      }

      @Test
      @DisplayName("X963KDF produces consistent results")
      void testX963KDFConsistency() throws Exception {
         KDF kdf = KDF.getInstance("X963KDF-SHA256", "Glassless");

         byte[] sharedSecret = "shared-secret-value-1234".getBytes();
         byte[] sharedInfo = "info".getBytes();

         X963KDFParameterSpec params1 = new X963KDFParameterSpec(sharedSecret, sharedInfo, 16);
         X963KDFParameterSpec params2 = new X963KDFParameterSpec(sharedSecret, sharedInfo, 16);

         byte[] derived1 = kdf.deriveData(params1);
         byte[] derived2 = kdf.deriveData(params2);

         assertArrayEquals(derived1, derived2, "Same inputs should produce same output");
      }
   }

   @Nested
   @DisplayName("SSH KDF Tests")
   class SSHKDFTests {

      @Test
      @DisplayName("SSHKDF-SHA256 basic derivation")
      void testSSHKDFSHA256() throws Exception {
         KDF kdf = KDF.getInstance("SSHKDF-SHA256", "Glassless");
         assertNotNull(kdf);

         byte[] sharedSecret = new byte[32];
         for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;
         byte[] exchangeHash = new byte[32];
         for (int i = 0; i < 32; i++) exchangeHash[i] = (byte) (i + 32);
         byte[] sessionId = new byte[32];
         for (int i = 0; i < 32; i++) sessionId[i] = (byte) (i + 64);

         SSHKDFParameterSpec params = new SSHKDFParameterSpec(
            sharedSecret, exchangeHash, sessionId,
            SSHKDFParameterSpec.TYPE_ENCRYPTION_KEY_CLI_TO_SRV, 32);
         SecretKey key = kdf.deriveKey("AES", params);

         assertNotNull(key);
         assertEquals("AES", key.getAlgorithm());
         assertEquals(32, key.getEncoded().length);
      }

      @Test
      @DisplayName("Different key types produce different keys")
      void testSSHKDFKeyTypes() throws Exception {
         KDF kdf = KDF.getInstance("SSHKDF-SHA256", "Glassless");

         byte[] sharedSecret = "ssh-shared-secret".getBytes();
         byte[] exchangeHash = "ssh-exchange-hash!".getBytes();
         byte[] sessionId = "ssh-session-id!!!".getBytes();

         SSHKDFParameterSpec paramsC = new SSHKDFParameterSpec(
            sharedSecret, exchangeHash, sessionId,
            SSHKDFParameterSpec.TYPE_ENCRYPTION_KEY_CLI_TO_SRV, 16);
         SSHKDFParameterSpec paramsD = new SSHKDFParameterSpec(
            sharedSecret, exchangeHash, sessionId,
            SSHKDFParameterSpec.TYPE_ENCRYPTION_KEY_SRV_TO_CLI, 16);

         byte[] keyC = kdf.deriveData(paramsC);
         byte[] keyD = kdf.deriveData(paramsD);

         assertFalse(java.util.Arrays.equals(keyC, keyD),
            "Different key types should produce different keys");
      }
   }

   @Nested
   @DisplayName("KBKDF Tests")
   class KBKDFTests {

      @Test
      @DisplayName("KBKDF-HMAC-SHA256 basic derivation")
      void testKBKDFHMACSHA256() throws Exception {
         KDF kdf = KDF.getInstance("KBKDF-HMAC-SHA256", "Glassless");
         assertNotNull(kdf);

         byte[] key = new byte[32];
         for (int i = 0; i < 32; i++) key[i] = (byte) i;
         byte[] label = "label".getBytes();
         byte[] context = "context".getBytes();

         KBKDFParameterSpec params = new KBKDFParameterSpec(key, label, context, 32);
         SecretKey derivedKey = kdf.deriveKey("AES", params);

         assertNotNull(derivedKey);
         assertEquals("AES", derivedKey.getAlgorithm());
         assertEquals(32, derivedKey.getEncoded().length);
      }
   }

   @Nested
   @DisplayName("TLS PRF Tests")
   class TLSPRFTests {

      @Test
      @DisplayName("TLS1-PRF-SHA256 basic derivation")
      void testTLSPRFSHA256() throws Exception {
         KDF kdf = KDF.getInstance("TLS1-PRF-SHA256", "Glassless");
         assertNotNull(kdf);

         byte[] secret = new byte[48];  // Pre-master secret size
         for (int i = 0; i < 48; i++) secret[i] = (byte) i;
         byte[] clientRandom = new byte[32];
         byte[] serverRandom = new byte[32];
         for (int i = 0; i < 32; i++) {
            clientRandom[i] = (byte) (i + 100);
            serverRandom[i] = (byte) (i + 200);
         }

         // Combine randoms for seed
         byte[] seed = new byte[64];
         System.arraycopy(clientRandom, 0, seed, 0, 32);
         System.arraycopy(serverRandom, 0, seed, 32, 32);

         TLSPRFParameterSpec params = new TLSPRFParameterSpec(
            secret, "master secret", seed, 48);
         SecretKey masterSecret = kdf.deriveKey("TLS", params);

         assertNotNull(masterSecret);
         assertEquals(48, masterSecret.getEncoded().length);
      }

      @Test
      @DisplayName("TLS1-PRF-SHA384 basic derivation")
      void testTLSPRFSHA384() throws Exception {
         KDF kdf = KDF.getInstance("TLS1-PRF-SHA384", "Glassless");
         assertNotNull(kdf);

         byte[] secret = new byte[48];
         for (int i = 0; i < 48; i++) secret[i] = (byte) i;
         byte[] seed = new byte[64];
         for (int i = 0; i < 64; i++) seed[i] = (byte) (i + 50);

         TLSPRFParameterSpec params = new TLSPRFParameterSpec(
            secret, "key expansion", seed, 128);
         byte[] keyBlock = kdf.deriveData(params);

         assertNotNull(keyBlock);
         assertEquals(128, keyBlock.length);
      }
   }
}
