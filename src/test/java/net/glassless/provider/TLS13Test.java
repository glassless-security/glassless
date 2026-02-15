package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Tests that simulate full TLS 1.3 client/server connections using the GlaSSLess provider.
 * These tests verify that the provider's algorithms work correctly together in a realistic
 * TLS handshake and data transfer scenario.
 */
public class TLS13Test {

   private static final String TEST_MESSAGE = "Hello from TLS 1.3 test! Testing encryption.";
   private static final char[] PASSWORD = "changeit".toCharArray();

   @TempDir
   Path tempDir;

   @BeforeAll
   public static void setUp() {
      Security.addProvider(new GlaSSLessProvider());
   }

   @Nested
   @DisplayName("TLS 1.3 with ECDSA certificates")
   class ECDSATests {

      @Test
      @DisplayName("TLS 1.3 handshake with P-256 ECDSA certificate")
      @Timeout(60)
      void testTLS13WithP256ECDSA() throws Exception {
         runTLSTest("EC", 256, "SHA256withECDSA");
      }

      @Test
      @DisplayName("TLS 1.3 handshake with P-384 ECDSA certificate")
      @Timeout(60)
      void testTLS13WithP384ECDSA() throws Exception {
         runTLSTest("EC", 384, "SHA384withECDSA");
      }
   }

   @Nested
   @DisplayName("TLS 1.3 with RSA certificates")
   class RSATests {

      @Test
      @DisplayName("TLS 1.3 handshake with RSA-2048 certificate")
      @Timeout(60)
      void testTLS13WithRSA2048() throws Exception {
         runTLSTest("RSA", 2048, "SHA256withRSA");
      }
   }

   @Nested
   @DisplayName("TLS data transfer tests")
   class DataTransferTests {

      @Test
      @DisplayName("Large data transfer over TLS 1.3")
      @Timeout(120)
      void testLargeDataTransfer() throws Exception {
         // Generate 100KB of random data
         byte[] largeData = new byte[100 * 1024];
         SecureRandom random = SecureRandom.getInstance("NativePRNG", "GlaSSLess");
         random.nextBytes(largeData);

         KeyStore[] stores = generateKeyStoreWithKeytool("EC", 256, "SHA256withECDSA");
         KeyStore keyStore = stores[0];
         KeyStore trustStore = stores[1];

         SSLContext serverContext = createSSLContext(keyStore, PASSWORD);
         SSLContext clientContext = createClientSSLContext(trustStore);

         AtomicReference<Integer> serverPort = new AtomicReference<>();
         CountDownLatch serverReady = new CountDownLatch(1);
         AtomicReference<Exception> error = new AtomicReference<>();
         AtomicReference<byte[]> receivedData = new AtomicReference<>();

         // Server thread
         Thread serverThread = new Thread(() -> {
            try (SSLServerSocket serverSocket = (SSLServerSocket) serverContext
                  .getServerSocketFactory().createServerSocket(0)) {
               serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
               serverPort.set(serverSocket.getLocalPort());
               serverReady.countDown();

               try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                  InputStream in = socket.getInputStream();
                  OutputStream out = socket.getOutputStream();

                  // Read length prefix
                  byte[] lenBytes = in.readNBytes(4);
                  int len = ((lenBytes[0] & 0xFF) << 24) | ((lenBytes[1] & 0xFF) << 16)
                        | ((lenBytes[2] & 0xFF) << 8) | (lenBytes[3] & 0xFF);

                  // Read data
                  byte[] data = in.readNBytes(len);
                  receivedData.set(data);

                  // Send back hash as acknowledgment
                  java.security.MessageDigest md =
                        java.security.MessageDigest.getInstance("SHA-256", "GlaSSLess");
                  byte[] hash = md.digest(data);
                  out.write(hash);
                  out.flush();
               }
            } catch (Exception e) {
               error.set(e);
            }
         });
         serverThread.start();

         assertTrue(serverReady.await(30, TimeUnit.SECONDS), "Server failed to start");

         // Client
         try (SSLSocket clientSocket = (SSLSocket) clientContext.getSocketFactory()
               .createSocket("localhost", serverPort.get())) {
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.startHandshake();

            OutputStream out = clientSocket.getOutputStream();
            InputStream in = clientSocket.getInputStream();

            // Send length prefix and data
            out.write(new byte[]{
               (byte) (largeData.length >> 24),
               (byte) (largeData.length >> 16),
               (byte) (largeData.length >> 8),
               (byte) largeData.length
            });
            out.write(largeData);
            out.flush();

            // Read hash acknowledgment
            byte[] receivedHash = in.readNBytes(32);

            // Verify hash
            java.security.MessageDigest md =
                  java.security.MessageDigest.getInstance("SHA-256", "GlaSSLess");
            byte[] expectedHash = md.digest(largeData);
            assertArrayEquals(expectedHash, receivedHash, "Data integrity check failed");
         }

         serverThread.join(30000);

         if (error.get() != null) {
            throw error.get();
         }

         assertNotNull(receivedData.get());
         assertArrayEquals(largeData, receivedData.get(), "Large data transfer failed");
      }
   }

   @Nested
   @DisplayName("TLS cipher suite tests")
   class CipherSuiteTests {

      @Test
      @DisplayName("TLS 1.3 with TLS_AES_256_GCM_SHA384")
      @Timeout(60)
      void testTLS13AES256GCM() throws Exception {
         runTLSTestWithCipherSuite("EC", 384, "SHA384withECDSA", "TLS_AES_256_GCM_SHA384");
      }

      @Test
      @DisplayName("TLS 1.3 with TLS_AES_128_GCM_SHA256")
      @Timeout(60)
      void testTLS13AES128GCM() throws Exception {
         runTLSTestWithCipherSuite("EC", 256, "SHA256withECDSA", "TLS_AES_128_GCM_SHA256");
      }
   }

   @Nested
   @DisplayName("TLS algorithm verification")
   class AlgorithmVerificationTests {

      @Test
      @DisplayName("Verify GlaSSLess algorithms are used for crypto operations")
      @Timeout(30)
      void testGlaSSLessAlgorithmsUsed() throws Exception {
         // Test that we can get algorithms from GlaSSLess
         assertNotNull(java.security.MessageDigest.getInstance("SHA-256", "GlaSSLess"));
         assertNotNull(javax.crypto.Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess"));
         assertNotNull(javax.crypto.Mac.getInstance("HmacSHA256", "GlaSSLess"));
         assertNotNull(KeyPairGenerator.getInstance("EC", "GlaSSLess"));
         assertNotNull(java.security.Signature.getInstance("SHA256withECDSA", "GlaSSLess"));
         assertNotNull(SecureRandom.getInstance("NativePRNG", "GlaSSLess"));
      }

      @Test
      @DisplayName("Test HKDF key derivation (used by TLS 1.3)")
      @Timeout(10)
      void testHKDFKeyDerivation() throws Exception {
         // TLS 1.3 uses HKDF for key derivation
         javax.crypto.KDF hkdf = javax.crypto.KDF.getInstance("HKDF-SHA256", "GlaSSLess");
         assertNotNull(hkdf);

         byte[] ikm = "input-key-material".getBytes();
         byte[] salt = "salt".getBytes();
         byte[] info = "tls13 derived".getBytes();

         // Test HKDF extract and expand
         javax.crypto.spec.HKDFParameterSpec params = javax.crypto.spec.HKDFParameterSpec
               .ofExtract()
               .addIKM(ikm)
               .addSalt(salt)
               .thenExpand(info, 32);

         javax.crypto.SecretKey derived = hkdf.deriveKey("AES", params);
         assertNotNull(derived);
         assertEquals(32, derived.getEncoded().length);
      }

      @Test
      @DisplayName("Test AES-GCM encryption (used by TLS 1.3)")
      @Timeout(10)
      void testAESGCMEncryption() throws Exception {
         // TLS 1.3 uses AES-GCM for bulk encryption
         javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");

         javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES", "GlaSSLess");
         keyGen.init(256);
         javax.crypto.SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         SecureRandom.getInstance("NativePRNG", "GlaSSLess").nextBytes(iv);

         javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);

         // Encrypt
         cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, gcmSpec);
         byte[] plaintext = "TLS 1.3 application data".getBytes();
         byte[] ciphertext = cipher.doFinal(plaintext);

         // Decrypt
         cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, gcmSpec);
         byte[] decrypted = cipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted);
      }
   }

   @Nested
   @DisplayName("TLS 1.3 Hybrid Key Exchange Simulation")
   class HybridKeyExchangeTests {

      /**
       * Simulates a TLS 1.3 hybrid key exchange using X25519MLKEM768.
       * This test exercises the hybrid KEM in a TLS-like scenario:
       * 1. Server generates hybrid key pair
       * 2. Client encapsulates a shared secret using server's public key
       * 3. Server decapsulates to recover the shared secret
       * 4. Both sides derive traffic keys using HKDF (as in TLS 1.3)
       * 5. Verify encryption/decryption works with derived keys
       */
      @Test
      @DisplayName("Hybrid key exchange with X25519MLKEM768 and TLS 1.3 key derivation")
      @Timeout(30)
      void testHybridKeyExchangeX25519MLKEM768() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         // Server generates hybrid key pair
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KeyPair serverKeyPair = kpg.generateKeyPair();

         // Client encapsulates shared secret using server's public key
         KEM kem = KEM.getInstance("X25519MLKEM768", "GlaSSLess");
         KEM.Encapsulator encapsulator = kem.newEncapsulator(serverKeyPair.getPublic());
         KEM.Encapsulated encapsulated = encapsulator.encapsulate();

         byte[] clientSharedSecret = encapsulated.key().getEncoded();
         byte[] ciphertext = encapsulated.encapsulation();

         // Server decapsulates to get the same shared secret
         KEM.Decapsulator decapsulator = kem.newDecapsulator(serverKeyPair.getPrivate());
         SecretKey serverSharedSecretKey = decapsulator.decapsulate(ciphertext);
         byte[] serverSharedSecret = serverSharedSecretKey.getEncoded();

         // Verify both sides have the same shared secret
         assertArrayEquals(clientSharedSecret, serverSharedSecret,
            "Client and server must derive the same shared secret");
         assertEquals(64, clientSharedSecret.length,
            "X25519MLKEM768 shared secret should be 64 bytes");

         // Derive TLS 1.3 traffic keys using HKDF (as per RFC 8446)
         javax.crypto.KDF hkdf = javax.crypto.KDF.getInstance("HKDF-SHA256", "GlaSSLess");

         // Simulate TLS 1.3 key schedule: extract -> expand for client/server keys
         byte[] earlySecret = new byte[32]; // All zeros for initial extraction
         byte[] context = "tls13 hybrid test".getBytes();

         // Client write key derivation
         javax.crypto.spec.HKDFParameterSpec clientKeyParams = javax.crypto.spec.HKDFParameterSpec
               .ofExtract()
               .addIKM(clientSharedSecret)
               .addSalt(earlySecret)
               .thenExpand(context, 32);
         SecretKey clientWriteKey = hkdf.deriveKey("AES", clientKeyParams);

         // Server derives the same key from its shared secret
         javax.crypto.spec.HKDFParameterSpec serverKeyParams = javax.crypto.spec.HKDFParameterSpec
               .ofExtract()
               .addIKM(serverSharedSecret)
               .addSalt(earlySecret)
               .thenExpand(context, 32);
         SecretKey serverReadKey = hkdf.deriveKey("AES", serverKeyParams);

         // Verify derived keys match
         assertArrayEquals(clientWriteKey.getEncoded(), serverReadKey.getEncoded(),
            "Derived keys must match on both sides");

         // Test actual encryption/decryption with derived keys
         javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
         byte[] iv = new byte[12];
         SecureRandom.getInstance("NativePRNG", "GlaSSLess").nextBytes(iv);
         javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);

         // Client encrypts
         cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, clientWriteKey, gcmSpec);
         byte[] plaintext = "Hybrid PQC protected message".getBytes();
         byte[] encrypted = cipher.doFinal(plaintext);

         // Server decrypts
         cipher.init(javax.crypto.Cipher.DECRYPT_MODE, serverReadKey, gcmSpec);
         byte[] decrypted = cipher.doFinal(encrypted);

         assertArrayEquals(plaintext, decrypted, "Decryption must recover original plaintext");

         System.out.println("Hybrid key exchange test passed: X25519MLKEM768 with TLS 1.3 key derivation");
      }

      @Test
      @DisplayName("Hybrid key exchange with X448MLKEM1024 and TLS 1.3 key derivation")
      @Timeout(30)
      void testHybridKeyExchangeX448MLKEM1024() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X448MLKEM1024"),
            "X448MLKEM1024 requires OpenSSL 3.5+");

         // Server generates hybrid key pair
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X448MLKEM1024", "GlaSSLess");
         KeyPair serverKeyPair = kpg.generateKeyPair();

         // Client encapsulates
         KEM kem = KEM.getInstance("X448MLKEM1024", "GlaSSLess");
         KEM.Encapsulator encapsulator = kem.newEncapsulator(serverKeyPair.getPublic());
         KEM.Encapsulated encapsulated = encapsulator.encapsulate();

         // Server decapsulates
         KEM.Decapsulator decapsulator = kem.newDecapsulator(serverKeyPair.getPrivate());
         SecretKey serverSharedSecret = decapsulator.decapsulate(encapsulated.encapsulation());

         // Verify shared secrets match
         assertArrayEquals(encapsulated.key().getEncoded(), serverSharedSecret.getEncoded(),
            "Shared secrets must match");

         // Derive traffic keys using HKDF-SHA384 (appropriate for higher security)
         javax.crypto.KDF hkdf = javax.crypto.KDF.getInstance("HKDF-SHA384", "GlaSSLess");
         byte[] salt = new byte[48];
         byte[] info = "tls13 x448mlkem1024 test".getBytes();

         javax.crypto.spec.HKDFParameterSpec keyParams = javax.crypto.spec.HKDFParameterSpec
               .ofExtract()
               .addIKM(encapsulated.key().getEncoded())
               .addSalt(salt)
               .thenExpand(info, 32);
         SecretKey trafficKey = hkdf.deriveKey("AES", keyParams);

         assertNotNull(trafficKey);
         assertEquals(32, trafficKey.getEncoded().length);

         System.out.println("Hybrid key exchange test passed: X448MLKEM1024 with TLS 1.3 key derivation");
      }

      @Test
      @DisplayName("Multiple hybrid key exchanges (simulating session resumption)")
      @Timeout(60)
      void testMultipleHybridKeyExchanges() throws Exception {
         assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "X25519MLKEM768"),
            "X25519MLKEM768 requires OpenSSL 3.5+");

         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519MLKEM768", "GlaSSLess");
         KEM kem = KEM.getInstance("X25519MLKEM768", "GlaSSLess");

         // Simulate multiple handshakes (e.g., different clients connecting)
         for (int i = 0; i < 5; i++) {
            KeyPair serverKeyPair = kpg.generateKeyPair();

            KEM.Encapsulator encapsulator = kem.newEncapsulator(serverKeyPair.getPublic());
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();

            KEM.Decapsulator decapsulator = kem.newDecapsulator(serverKeyPair.getPrivate());
            SecretKey decapsulatedKey = decapsulator.decapsulate(encapsulated.encapsulation());

            assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded(),
               "Handshake " + (i + 1) + " failed: shared secrets don't match");
         }

         System.out.println("Multiple hybrid key exchange test passed: 5 successful handshakes");
      }
   }

   // Helper methods

   private KeyStore[] generateKeyStoreWithKeytool(String keyAlg, int keySize, String sigAlg)
         throws Exception {
      Path keystorePath = tempDir.resolve("keystore-" + System.nanoTime() + ".p12");

      // Build keytool command - use -groupname for EC, -keysize for RSA
      java.util.List<String> command = new java.util.ArrayList<>(java.util.List.of(
         "keytool",
         "-genkeypair",
         "-alias", "server",
         "-keyalg", keyAlg
      ));

      if ("EC".equals(keyAlg)) {
         // Map key size to curve name for EC keys
         String groupName = switch (keySize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported EC key size: " + keySize);
         };
         command.addAll(java.util.List.of("-groupname", groupName));
      } else {
         command.addAll(java.util.List.of("-keysize", String.valueOf(keySize)));
      }

      command.addAll(java.util.List.of(
         "-sigalg", sigAlg,
         "-validity", "365",
         "-keystore", keystorePath.toString(),
         "-storepass", new String(PASSWORD),
         "-keypass", new String(PASSWORD),
         "-dname", "CN=test-server,O=Test,C=US",
         "-storetype", "PKCS12"
      ));

      ProcessBuilder pb = new ProcessBuilder(command);
      pb.inheritIO();
      Process process = pb.start();
      int exitCode = process.waitFor();
      if (exitCode != 0) {
         throw new RuntimeException("keytool failed with exit code " + exitCode);
      }

      // Load the keystore
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream fis = new FileInputStream(keystorePath.toFile())) {
         keyStore.load(fis, PASSWORD);
      }

      // Create trust store with the same certificate
      KeyStore trustStore = KeyStore.getInstance("PKCS12");
      trustStore.load(null, PASSWORD);
      trustStore.setCertificateEntry("server", keyStore.getCertificate("server"));

      return new KeyStore[]{keyStore, trustStore};
   }

   private SSLContext createSSLContext(KeyStore keyStore, char[] password) throws Exception {
      KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(keyStore, password);

      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(keyStore);

      SSLContext ctx = SSLContext.getInstance("TLSv1.3");
      ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(),
            SecureRandom.getInstance("NativePRNG", "GlaSSLess"));

      return ctx;
   }

   private SSLContext createClientSSLContext(KeyStore trustStore) throws Exception {
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);

      SSLContext ctx = SSLContext.getInstance("TLSv1.3");
      ctx.init(null, tmf.getTrustManagers(),
            SecureRandom.getInstance("NativePRNG", "GlaSSLess"));

      return ctx;
   }

   private void runTLSTest(String keyAlg, int keySize, String sigAlg) throws Exception {
      KeyStore[] stores = generateKeyStoreWithKeytool(keyAlg, keySize, sigAlg);
      runTLSTestWithStores(stores[0], stores[1], "TLSv1.3");
   }

   private void runTLSTestWithStores(KeyStore keyStore, KeyStore trustStore, String protocol)
         throws Exception {
      SSLContext serverContext = createSSLContext(keyStore, PASSWORD);
      SSLContext clientContext = createClientSSLContext(trustStore);

      AtomicReference<Integer> serverPort = new AtomicReference<>();
      CountDownLatch serverReady = new CountDownLatch(1);
      AtomicReference<Exception> serverError = new AtomicReference<>();
      AtomicReference<String> receivedMessage = new AtomicReference<>();
      AtomicReference<String> negotiatedProtocol = new AtomicReference<>();
      AtomicReference<String> negotiatedCipherSuite = new AtomicReference<>();

      // Server thread
      Thread serverThread = new Thread(() -> {
         try (SSLServerSocket serverSocket = (SSLServerSocket) serverContext
               .getServerSocketFactory().createServerSocket(0)) {
            serverSocket.setEnabledProtocols(new String[]{protocol});
            serverPort.set(serverSocket.getLocalPort());
            serverReady.countDown();

            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
               socket.startHandshake();
               negotiatedProtocol.set(socket.getSession().getProtocol());
               negotiatedCipherSuite.set(socket.getSession().getCipherSuite());

               InputStream in = socket.getInputStream();
               OutputStream out = socket.getOutputStream();

               // Read message
               byte[] lenBytes = in.readNBytes(4);
               int len = ((lenBytes[0] & 0xFF) << 24) | ((lenBytes[1] & 0xFF) << 16)
                     | ((lenBytes[2] & 0xFF) << 8) | (lenBytes[3] & 0xFF);
               byte[] data = in.readNBytes(len);
               receivedMessage.set(new String(data, "UTF-8"));

               // Echo back
               out.write(lenBytes);
               out.write(data);
               out.flush();
            }
         } catch (Exception e) {
            serverError.set(e);
         }
      });
      serverThread.start();

      assertTrue(serverReady.await(30, TimeUnit.SECONDS), "Server failed to start");

      // Client
      String echoedMessage;
      try (SSLSocket clientSocket = (SSLSocket) clientContext.getSocketFactory()
            .createSocket("localhost", serverPort.get())) {
         clientSocket.setEnabledProtocols(new String[]{protocol});
         clientSocket.startHandshake();

         OutputStream out = clientSocket.getOutputStream();
         InputStream in = clientSocket.getInputStream();

         // Send message
         byte[] msgBytes = TEST_MESSAGE.getBytes("UTF-8");
         out.write(new byte[]{
            (byte) (msgBytes.length >> 24),
            (byte) (msgBytes.length >> 16),
            (byte) (msgBytes.length >> 8),
            (byte) msgBytes.length
         });
         out.write(msgBytes);
         out.flush();

         // Read echo
         byte[] lenBytes = in.readNBytes(4);
         int len = ((lenBytes[0] & 0xFF) << 24) | ((lenBytes[1] & 0xFF) << 16)
               | ((lenBytes[2] & 0xFF) << 8) | (lenBytes[3] & 0xFF);
         byte[] data = in.readNBytes(len);
         echoedMessage = new String(data, "UTF-8");
      }

      serverThread.join(30000);

      if (serverError.get() != null) {
         throw serverError.get();
      }

      assertEquals(protocol, negotiatedProtocol.get(), "Wrong protocol negotiated");
      assertEquals(TEST_MESSAGE, receivedMessage.get(), "Server received wrong message");
      assertEquals(TEST_MESSAGE, echoedMessage, "Client received wrong echo");

      // Log the cipher suite used
      System.out.println("TLS test passed: " + protocol + " with " + negotiatedCipherSuite.get());
   }

   private void runTLSTestWithCipherSuite(String keyAlg, int keySize, String sigAlg, String cipherSuite)
         throws Exception {
      KeyStore[] stores = generateKeyStoreWithKeytool(keyAlg, keySize, sigAlg);
      KeyStore keyStore = stores[0];
      KeyStore trustStore = stores[1];

      SSLContext serverContext = createSSLContext(keyStore, PASSWORD);
      SSLContext clientContext = createClientSSLContext(trustStore);

      AtomicReference<Integer> serverPort = new AtomicReference<>();
      CountDownLatch serverReady = new CountDownLatch(1);
      AtomicReference<Exception> serverError = new AtomicReference<>();
      AtomicReference<String> negotiatedCipherSuite = new AtomicReference<>();

      // Server thread
      Thread serverThread = new Thread(() -> {
         try (SSLServerSocket serverSocket = (SSLServerSocket) serverContext
               .getServerSocketFactory().createServerSocket(0)) {
            serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            serverSocket.setEnabledCipherSuites(new String[]{cipherSuite});
            serverPort.set(serverSocket.getLocalPort());
            serverReady.countDown();

            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
               socket.startHandshake();
               negotiatedCipherSuite.set(socket.getSession().getCipherSuite());

               InputStream in = socket.getInputStream();
               OutputStream out = socket.getOutputStream();

               // Simple echo
               byte[] buffer = new byte[1024];
               int read = in.read(buffer);
               if (read > 0) {
                  out.write(buffer, 0, read);
                  out.flush();
               }
            }
         } catch (Exception e) {
            serverError.set(e);
         }
      });
      serverThread.start();

      assertTrue(serverReady.await(30, TimeUnit.SECONDS), "Server failed to start");

      // Client
      try (SSLSocket clientSocket = (SSLSocket) clientContext.getSocketFactory()
            .createSocket("localhost", serverPort.get())) {
         clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
         clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});
         clientSocket.startHandshake();

         OutputStream out = clientSocket.getOutputStream();
         InputStream in = clientSocket.getInputStream();

         out.write("test".getBytes());
         out.flush();

         byte[] response = new byte[4];
         int read = in.read(response);
         assertEquals(4, read);
         assertEquals("test", new String(response, 0, read));
      }

      serverThread.join(30000);

      if (serverError.get() != null) {
         throw serverError.get();
      }

      assertEquals(cipherSuite, negotiatedCipherSuite.get(),
            "Expected cipher suite " + cipherSuite + " but got " + negotiatedCipherSuite.get());

      System.out.println("TLS cipher suite test passed: " + cipherSuite);
   }
}
