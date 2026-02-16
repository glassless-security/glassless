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
import net.glassless.provider.internal.kdf.TLS13KDFParameterSpec;
import net.glassless.provider.internal.kdf.TLSPRFParameterSpec;
import net.glassless.provider.internal.kdf.X963KDFParameterSpec;

/**
 * Tests for KDF implementations.
 */
public class KDFTest {

   @BeforeAll
   public static void setUp() {
      Security.addProvider(new GlaSSLessProvider());
   }

   @Nested
   @DisplayName("X9.63 KDF Tests")
   class X963KDFTests {

      @Test
      @DisplayName("X963KDF-SHA256 basic derivation")
      void testX963KDFSHA256() throws Exception {
         KDF kdf = KDF.getInstance("X963KDF-SHA256", "GlaSSLess");
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
         KDF kdf = KDF.getInstance("X963KDF-SHA256", "GlaSSLess");

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
         KDF kdf = KDF.getInstance("SSHKDF-SHA256", "GlaSSLess");
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
         KDF kdf = KDF.getInstance("SSHKDF-SHA256", "GlaSSLess");

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
         KDF kdf = KDF.getInstance("KBKDF-HMAC-SHA256", "GlaSSLess");
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
         KDF kdf = KDF.getInstance("TLS1-PRF-SHA256", "GlaSSLess");
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
         KDF kdf = KDF.getInstance("TLS1-PRF-SHA384", "GlaSSLess");
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

   @Nested
   @DisplayName("TLS 1.3 KDF Tests")
   class TLS13KDFTests {

      @Test
      @DisplayName("TLS13-KDF-SHA256 extract mode")
      void testTLS13KDFSHA256Extract() throws Exception {
         KDF kdf = KDF.getInstance("TLS13-KDF-SHA256", "GlaSSLess");
         assertNotNull(kdf);

         // Input key material (e.g., ECDHE shared secret)
         byte[] ikm = new byte[32];
         for (int i = 0; i < 32; i++) ikm[i] = (byte) i;

         // Salt (e.g., previous secret in TLS 1.3 key schedule)
         byte[] salt = new byte[32];
         for (int i = 0; i < 32; i++) salt[i] = (byte) (i + 100);

         // Extract PRK (SHA-256 output = 32 bytes)
         TLS13KDFParameterSpec params = TLS13KDFParameterSpec
            .forExtract(ikm, salt, 32)
            .build();

         SecretKey prk = kdf.deriveKey("TLS13-PRK", params);

         assertNotNull(prk);
         assertEquals(32, prk.getEncoded().length);
      }

      @Test
      @DisplayName("TLS13-KDF-SHA256 expand mode")
      void testTLS13KDFSHA256Expand() throws Exception {
         KDF kdf = KDF.getInstance("TLS13-KDF-SHA256", "GlaSSLess");

         // First extract a PRK
         byte[] ikm = new byte[32];
         for (int i = 0; i < 32; i++) ikm[i] = (byte) i;
         byte[] salt = new byte[32];

         TLS13KDFParameterSpec extractParams = TLS13KDFParameterSpec
            .forExtract(ikm, salt, 32)
            .build();
         byte[] prk = kdf.deriveData(extractParams);

         // Now expand to derive a traffic key
         byte[] context = new byte[32];  // Handshake hash
         for (int i = 0; i < 32; i++) context[i] = (byte) (i + 50);

         TLS13KDFParameterSpec expandParams = TLS13KDFParameterSpec
            .forExpand(prk, "key", context, 16)
            .build();

         SecretKey trafficKey = kdf.deriveKey("AES", expandParams);

         assertNotNull(trafficKey);
         assertEquals("AES", trafficKey.getAlgorithm());
         assertEquals(16, trafficKey.getEncoded().length);
      }

      @Test
      @DisplayName("TLS13-KDF-SHA384 extract and expand")
      void testTLS13KDFSHA384() throws Exception {
         KDF kdf = KDF.getInstance("TLS13-KDF-SHA384", "GlaSSLess");
         assertNotNull(kdf);

         // Input key material
         byte[] ikm = new byte[48];
         for (int i = 0; i < 48; i++) ikm[i] = (byte) i;

         // Extract PRK (SHA-384 output = 48 bytes)
         TLS13KDFParameterSpec extractParams = TLS13KDFParameterSpec
            .forExtract(ikm, null, 48)
            .build();
         byte[] prk = kdf.deriveData(extractParams);

         assertNotNull(prk);
         assertEquals(48, prk.length);

         // Expand to derive IV
         TLS13KDFParameterSpec expandParams = TLS13KDFParameterSpec
            .forExpand(prk, "iv", new byte[0], 12)
            .build();

         byte[] iv = kdf.deriveData(expandParams);

         assertNotNull(iv);
         assertEquals(12, iv.length);
      }

      @Test
      @DisplayName("Different labels produce different keys")
      void testDifferentLabels() throws Exception {
         KDF kdf = KDF.getInstance("TLS13-KDF-SHA256", "GlaSSLess");

         byte[] prk = new byte[32];
         for (int i = 0; i < 32; i++) prk[i] = (byte) (i * 3);
         byte[] context = new byte[32];

         TLS13KDFParameterSpec keyParams = TLS13KDFParameterSpec
            .forExpand(prk, "key", context, 16)
            .build();
         TLS13KDFParameterSpec ivParams = TLS13KDFParameterSpec
            .forExpand(prk, "iv", context, 12)
            .build();

         byte[] keyData = kdf.deriveData(keyParams);
         byte[] ivData = kdf.deriveData(ivParams);

         assertNotNull(keyData);
         assertNotNull(ivData);
         // Different labels should produce different output
         // (even if we only compare first 12 bytes)
         boolean different = false;
         for (int i = 0; i < 12; i++) {
            if (keyData[i] != ivData[i]) {
               different = true;
               break;
            }
         }
         assertTrue(different, "Different labels should produce different keys");
      }

      @Test
      @DisplayName("TLS 1.3 full key schedule simulation")
      void testTLS13KeySchedule() throws Exception {
         KDF kdf = KDF.getInstance("TLS13-KDF-SHA256", "GlaSSLess");

         // Simulate TLS 1.3 key schedule per RFC 8446 Section 7.1

         // 1. Early Secret = HKDF-Extract(salt=0, IKM=PSK or 0)
         byte[] zeroSalt = new byte[32];
         byte[] zeroPsk = new byte[32];  // No PSK case

         TLS13KDFParameterSpec earlyParams = TLS13KDFParameterSpec
            .forExtract(zeroPsk, zeroSalt, 32)
            .build();
         byte[] earlySecret = kdf.deriveData(earlyParams);
         assertNotNull(earlySecret);
         assertEquals(32, earlySecret.length);

         // 2. Derive-Secret for "derived" with empty hash
         byte[] emptyHash = new byte[32];  // SHA256 of empty string (simplified)
         TLS13KDFParameterSpec derivedParams = TLS13KDFParameterSpec
            .forExpand(earlySecret, "derived", emptyHash, 32)
            .build();
         byte[] derivedSecret = kdf.deriveData(derivedParams);
         assertNotNull(derivedSecret);

         // 3. Handshake Secret = HKDF-Extract(salt=derived_secret, IKM=ECDHE)
         byte[] ecdheSecret = new byte[32];
         for (int i = 0; i < 32; i++) ecdheSecret[i] = (byte) (i + 1);

         TLS13KDFParameterSpec hsParams = TLS13KDFParameterSpec
            .forExtract(ecdheSecret, derivedSecret, 32)
            .build();
         byte[] handshakeSecret = kdf.deriveData(hsParams);
         assertNotNull(handshakeSecret);
         assertEquals(32, handshakeSecret.length);

         // 4. Derive client handshake traffic secret
         byte[] handshakeHash = new byte[32];
         for (int i = 0; i < 32; i++) handshakeHash[i] = (byte) (i * 2);

         TLS13KDFParameterSpec chtsParams = TLS13KDFParameterSpec
            .forExpand(handshakeSecret, "c hs traffic", handshakeHash, 32)
            .build();
         byte[] clientHsTrafficSecret = kdf.deriveData(chtsParams);
         assertNotNull(clientHsTrafficSecret);
         assertEquals(32, clientHsTrafficSecret.length);

         // 5. Derive traffic key from client handshake traffic secret
         TLS13KDFParameterSpec keyParams = TLS13KDFParameterSpec
            .forExpand(clientHsTrafficSecret, "key", new byte[0], 16)
            .build();
         SecretKey trafficKey = kdf.deriveKey("AES", keyParams);
         assertNotNull(trafficKey);
         assertEquals("AES", trafficKey.getAlgorithm());
         assertEquals(16, trafficKey.getEncoded().length);

         // 6. Derive IV
         TLS13KDFParameterSpec ivParams = TLS13KDFParameterSpec
            .forExpand(clientHsTrafficSecret, "iv", new byte[0], 12)
            .build();
         byte[] iv = kdf.deriveData(ivParams);
         assertNotNull(iv);
         assertEquals(12, iv.length);
      }
   }
}
