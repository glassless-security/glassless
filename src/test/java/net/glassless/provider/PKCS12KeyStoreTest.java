package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests that PKCS12 keystores created by the JDK can be loaded when
 * GlaSSLess is registered as the highest-priority provider.
 * This validates that GlaSSLess's PBE Cipher, AlgorithmParameters,
 * and SecretKeyFactory implementations are compatible with the JDK's
 * PKCS12KeyStore, which uses PBES2 for encryption and PKCS#12 KDF
 * for MAC integrity checking.
 */
@DisplayName("PKCS12 KeyStore interoperability")
public class PKCS12KeyStoreTest {

   private static final char[] PASSWORD = "testPassword".toCharArray();
   private static final String PASSWORD_STR = "testPassword";

   @TempDir
   Path tempDir;

   @BeforeAll
   public static void setUp() {
      Security.insertProviderAt(new GlaSSLessProvider(), 1);
   }

   @Test
   @DisplayName("Load PKCS12 keystore with RSA key created by keytool")
   void testLoadPKCS12WithRSAKey() throws Exception {
      Path ksPath = generateKeystore("RSA", 2048);
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(Files.newInputStream(ksPath), PASSWORD);

      assertEquals(1, ks.size());
      assertTrue(ks.isKeyEntry("test"));
      assertNotNull(ks.getKey("test", PASSWORD));
      Certificate cert = ks.getCertificate("test");
      assertNotNull(cert);
      assertEquals("X.509", cert.getType());
   }

   @Test
   @DisplayName("Load PKCS12 keystore with EC key created by keytool")
   void testLoadPKCS12WithECKey() throws Exception {
      Path ksPath = generateKeystore("EC", 256);
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(Files.newInputStream(ksPath), PASSWORD);

      assertEquals(1, ks.size());
      assertTrue(ks.isKeyEntry("test"));
      assertNotNull(ks.getKey("test", PASSWORD));
   }

   @Test
   @DisplayName("Round-trip: load PKCS12, re-store, and load again")
   void testRoundTrip() throws Exception {
      Path ksPath = generateKeystore("RSA", 3072);

      // Load the keystore
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(Files.newInputStream(ksPath), PASSWORD);

      // Re-store with the same password
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ks.store(out, PASSWORD);

      // Load again
      KeyStore ks2 = KeyStore.getInstance("PKCS12");
      ks2.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);

      assertEquals(1, ks2.size());
      assertTrue(ks2.isKeyEntry("test"));
      assertNotNull(ks2.getKey("test", PASSWORD));

      // Verify the certificate chain is preserved
      Certificate[] chain = ks2.getCertificateChain("test");
      assertNotNull(chain);
      assertEquals(1, chain.length);
   }

   /**
    * Generates a PKCS12 keystore with a self-signed certificate using keytool.
    */
   private Path generateKeystore(String keyAlgorithm, int keySize) throws Exception {
      Path ksPath = tempDir.resolve("test-" + keyAlgorithm + ".p12");
      ProcessBuilder pb = new ProcessBuilder(
         "keytool", "-genkeypair",
         "-alias", "test",
         "-keyalg", keyAlgorithm,
         "-keysize", String.valueOf(keySize),
         "-dname", "CN=Test, O=GlaSSLess",
         "-validity", "365",
         "-storetype", "PKCS12",
         "-keystore", ksPath.toString(),
         "-storepass", PASSWORD_STR,
         "-keypass", PASSWORD_STR);
      pb.inheritIO();
      Process p = pb.start();
      int exit = p.waitFor();
      if (exit != 0) {
         throw new RuntimeException("keytool failed with exit code " + exit);
      }
      return ksPath;
   }
}
