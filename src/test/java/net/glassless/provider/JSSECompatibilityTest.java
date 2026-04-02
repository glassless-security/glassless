package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * JSSE compatibility tests with GlaSSLess as the HIGHEST-PRIORITY provider.
 * <p>
 * When GlaSSLess is installed at position 1, JSSE resolves all crypto services
 * (KeyPairGenerator, KeyFactory, AlgorithmParameters, Cipher, etc.) from GlaSSLess.
 * This exercises code paths that are NOT hit when GlaSSLess is a low-priority provider:
 * <ul>
 *   <li>ECParameterSpec (NamedCurve) handling in EC KeyPairGenerator</li>
 *   <li>KeyFactory delegation to avoid infinite recursion</li>
 *   <li>AlgorithmParameters EC → ECParameterSpec resolution</li>
 *   <li>ECDH/DH KeyAgreement accepting non-null params</li>
 *   <li>AES-GCM updateAAD and correct output size estimation</li>
 *   <li>ByteBuffer-based Cipher operations for TLS records</li>
 * </ul>
 */
public class JSSECompatibilityTest {

   private static GlaSSLessProvider provider;

   @TempDir
   Path tempDir;

   @BeforeAll
   public static void setUp() {
      provider = new GlaSSLessProvider();
      // Insert at position 1 — highest priority, just like a real deployment
      Security.insertProviderAt(provider, 1);
   }

   @AfterAll
   public static void tearDown() {
      Security.removeProvider(provider.getName());
   }

   @Nested
   @DisplayName("EC KeyPairGenerator with ECParameterSpec")
   class ECParameterSpecTests {

      @ParameterizedTest(name = "EC KeyPairGenerator with ECParameterSpec from {0}")
      @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
      @DisplayName("JSSE passes ECParameterSpec (NamedCurve), not ECGenParameterSpec")
      void testECKeyGenWithECParameterSpec(String curveName) throws Exception {
         // JSSE's NamedCurve extends ECParameterSpec. Simulate by extracting
         // ECParameterSpec from a generated key (same as what JSSE does).
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
         kpg.initialize(new ECGenParameterSpec(curveName));
         KeyPair seedPair = kpg.generateKeyPair();
         ECParameterSpec ecParams = ((ECPublicKey) seedPair.getPublic()).getParams();

         // This is the call JSSE makes — must not throw InvalidAlgorithmParameterException
         KeyPairGenerator glasslessKpg = KeyPairGenerator.getInstance("EC");
         glasslessKpg.initialize(ecParams);

         KeyPair keyPair = glasslessKpg.generateKeyPair();
         assertNotNull(keyPair);
         assertInstanceOf(ECPublicKey.class, keyPair.getPublic());
         assertInstanceOf(ECPrivateKey.class, keyPair.getPrivate());

         ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
         assertEquals(ecParams.getCurve().getField().getFieldSize(),
            pub.getParams().getCurve().getField().getFieldSize());
      }
   }

   @Nested
   @DisplayName("KeyFactory delegation (no StackOverflow)")
   class KeyFactoryDelegationTests {

      @ParameterizedTest(name = "KeyFactory {0} does not recurse")
      @ValueSource(strings = {"EC", "RSA"})
      void testKeyFactoryNoRecursion(String algorithm) throws Exception {
         // When GlaSSLess is highest priority, KeyFactory.getInstance("EC") returns
         // GlaSSLess KeyFactory. It must delegate to a non-GlaSSLess provider internally.
         KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
         if ("EC".equals(algorithm)) {
            kpg.initialize(256);
         } else {
            kpg.initialize(2048);
         }
         KeyPair keyPair = kpg.generateKeyPair();

         // Round-trip through KeyFactory — must not StackOverflow
         KeyFactory kf = KeyFactory.getInstance(algorithm);
         assertDoesNotThrow(() -> {
            kf.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
            kf.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
         });
      }
   }

   @Nested
   @DisplayName("AlgorithmParameters EC → ECParameterSpec")
   class AlgorithmParametersTests {

      @ParameterizedTest(name = "AlgorithmParameters EC resolves ECParameterSpec for {0}")
      @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
      void testECAlgorithmParametersReturnsECParameterSpec(String curveName) throws Exception {
         // SunEC's ECPublicKeyImpl calls AlgorithmParameters.getInstance("EC"),
         // inits from DER OID, then requests ECParameterSpec.
         java.security.AlgorithmParameters params =
            java.security.AlgorithmParameters.getInstance("EC");
         params.init(new ECGenParameterSpec(curveName));

         // Must not throw InvalidParameterSpecException
         ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
         assertNotNull(spec);

         int expectedFieldSize = switch (curveName) {
            case "secp256r1" -> 256;
            case "secp384r1" -> 384;
            case "secp521r1" -> 521;
            default -> throw new IllegalArgumentException();
         };
         assertEquals(expectedFieldSize, spec.getCurve().getField().getFieldSize());
      }

      @Test
      @DisplayName("EC AlgorithmParameters DER round-trip resolves ECParameterSpec")
      void testECAlgorithmParametersDERRoundTrip() throws Exception {
         // Simulate the exact JSSE flow: init from DER, then get ECParameterSpec
         java.security.AlgorithmParameters params1 =
            java.security.AlgorithmParameters.getInstance("EC");
         params1.init(new ECGenParameterSpec("secp256r1"));
         byte[] encoded = params1.getEncoded();

         java.security.AlgorithmParameters params2 =
            java.security.AlgorithmParameters.getInstance("EC");
         params2.init(encoded);

         ECParameterSpec spec = params2.getParameterSpec(ECParameterSpec.class);
         assertNotNull(spec);
         assertEquals(256, spec.getCurve().getField().getFieldSize());
      }
   }

   @Nested
   @DisplayName("KeyAgreement with non-null params")
   class KeyAgreementParamsTests {

      @Test
      @DisplayName("ECDH init with ECParameterSpec (JSSE passes NamedCurve)")
      void testECDHWithECParameterSpec() throws Exception {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
         kpg.initialize(new ECGenParameterSpec("secp256r1"));
         KeyPair alice = kpg.generateKeyPair();
         KeyPair bob = kpg.generateKeyPair();

         ECParameterSpec ecParams = ((ECPublicKey) alice.getPublic()).getParams();

         // JSSE calls init(key, ECParameterSpec, random) — must not throw
         KeyAgreement ka = KeyAgreement.getInstance("ECDH");
         ka.init(alice.getPrivate(), ecParams);
         ka.doPhase(bob.getPublic(), true);
         byte[] secret = ka.generateSecret();
         assertNotNull(secret);
         assertEquals(32, secret.length);
      }

      @Test
      @DisplayName("DH init with DHParameterSpec")
      void testDHWithDHParameterSpec() throws Exception {
         // Use SunJCE for key generation — GlaSSLess DHKeyPairGenerator generates
         // fresh DH params per key pair; both parties need shared params.
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "SunJCE");
         kpg.initialize(2048);
         KeyPair alice = kpg.generateKeyPair();
         KeyPair bob = kpg.generateKeyPair();

         javax.crypto.spec.DHParameterSpec dhParams =
            ((javax.crypto.interfaces.DHPublicKey) alice.getPublic()).getParams();

         // The point: GlaSSLess DH KeyAgreement must accept DHParameterSpec in init
         KeyAgreement ka = KeyAgreement.getInstance("DH",
            GlaSSLessProvider.PROVIDER_NAME);
         ka.init(alice.getPrivate(), dhParams);
         ka.doPhase(bob.getPublic(), true);
         byte[] secret = ka.generateSecret();
         assertNotNull(secret);
      }
   }

   @Nested
   @DisplayName("AES-GCM JSSE compatibility")
   class AESGCMTests {

      @Test
      @DisplayName("AES-GCM with updateAAD (TLS 1.3 record encryption)")
      void testAESGCMWithAAD() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12]; // TLS 1.3 uses 12-byte nonce
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         // Simulate TLS 1.3: AAD is the 5-byte record header
         byte[] aad = new byte[]{0x17, 0x03, 0x03, 0x00, 0x20};
         byte[] plaintext = "TLS application data payload".getBytes(StandardCharsets.UTF_8);

         // Encrypt with AAD
         cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(aad);
         byte[] ciphertext = cipher.doFinal(plaintext);

         // ciphertext should be plaintext.length + 16 (GCM tag)
         assertEquals(plaintext.length + 16, ciphertext.length);

         // Decrypt with AAD
         cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(aad);
         byte[] decrypted = cipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("AES-GCM with ByteBuffer updateAAD (JSSE uses ByteBuffer)")
      void testAESGCMWithByteBufferAAD() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = new byte[]{0x17, 0x03, 0x03, 0x00, 0x20};
         byte[] plaintext = "ByteBuffer AAD test".getBytes(StandardCharsets.UTF_8);

         // Encrypt with ByteBuffer AAD
         cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(ByteBuffer.wrap(aad));
         byte[] ciphertext = cipher.doFinal(plaintext);

         // Decrypt with ByteBuffer AAD
         cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(ByteBuffer.wrap(aad));
         byte[] decrypted = cipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("AES-GCM engineGetOutputSize is correct for JSSE buffer allocation")
      void testAESGCMOutputSize() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         // Encrypt mode: output must be >= plaintext + tag
         cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         int encryptOutputSize = cipher.getOutputSize(25);
         assertTrue(encryptOutputSize >= 25 + 16,
            "Encrypt output size must account for 16-byte GCM tag, got " + encryptOutputSize);

         // Decrypt mode: output must be <= ciphertext - tag
         cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         int decryptOutputSize = cipher.getOutputSize(41); // 25 bytes plaintext + 16 bytes tag
         assertTrue(decryptOutputSize <= 41,
            "Decrypt output size must not exceed input length, got " + decryptOutputSize);
      }

      @Test
      @DisplayName("AES-GCM doFinal with ByteBuffer (CipherSpi.bufferCrypt path)")
      void testAESGCMDoFinalWithByteBuffer() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = {0x17, 0x03, 0x03, 0x00, 0x1A};
         byte[] plaintext = "ByteBuffer doFinal test!".getBytes(StandardCharsets.UTF_8);

         // Encrypt using byte[] API
         cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(aad);
         byte[] ciphertext = cipher.doFinal(plaintext);

         // Decrypt using ByteBuffer API (the path JSSE takes)
         cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(aad);
         ByteBuffer inputBuf = ByteBuffer.wrap(ciphertext);
         ByteBuffer outputBuf = ByteBuffer.allocate(cipher.getOutputSize(ciphertext.length));
         int produced = cipher.doFinal(inputBuf, outputBuf);

         byte[] decrypted = new byte[produced];
         outputBuf.flip();
         outputBuf.get(decrypted);
         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("AES-128-GCM with AAD (TLS_AES_128_GCM_SHA256)")
      void testAES128GCMWithAAD() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_128/GCM/NoPadding");
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(128);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = {0x17, 0x03, 0x03, 0x00, 0x15};
         byte[] plaintext = "AES-128-GCM test".getBytes(StandardCharsets.UTF_8);

         cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(aad);
         byte[] ciphertext = cipher.doFinal(plaintext);

         cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         cipher.updateAAD(aad);
         byte[] decrypted = cipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("Cross-provider: SunJCE encrypts, GlaSSLess decrypts (simulates MySQL TLS)")
      void testCrossProviderGCMDecrypt() throws Exception {
         KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = {0x17, 0x03, 0x03, 0x00, 0x30};
         byte[] plaintext = "Cross-provider GCM test simulating MySQL TLS".getBytes(StandardCharsets.UTF_8);

         // Encrypt with SunJCE (simulates MySQL server)
         Cipher sunCipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
         sunCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         sunCipher.updateAAD(aad);
         byte[] ciphertext = sunCipher.doFinal(plaintext);

         // Decrypt with GlaSSLess (simulates Java client with GlaSSLess provider)
         Cipher glassCipher = Cipher.getInstance("AES/GCM/NoPadding",
            GlaSSLessProvider.PROVIDER_NAME);
         glassCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         glassCipher.updateAAD(aad);
         byte[] decrypted = glassCipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted,
            "Cross-provider GCM decryption must produce correct plaintext");
      }

      @Test
      @DisplayName("Cross-provider: GlaSSLess encrypts, SunJCE decrypts")
      void testCrossProviderGCMEncrypt() throws Exception {
         KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = {0x17, 0x03, 0x03, 0x00, 0x30};
         byte[] plaintext = "Reverse cross-provider GCM test".getBytes(StandardCharsets.UTF_8);

         // Encrypt with GlaSSLess
         Cipher glassCipher = Cipher.getInstance("AES/GCM/NoPadding",
            GlaSSLessProvider.PROVIDER_NAME);
         glassCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         glassCipher.updateAAD(aad);
         byte[] ciphertext = glassCipher.doFinal(plaintext);

         // Decrypt with SunJCE
         Cipher sunCipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
         sunCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         sunCipher.updateAAD(aad);
         byte[] decrypted = sunCipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("Cross-provider GCM with ByteBuffer doFinal (JSSE path)")
      void testCrossProviderGCMByteBuffer() throws Exception {
         KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = {0x17, 0x03, 0x03, 0x00, 0x20};
         byte[] plaintext = "ByteBuffer cross-provider".getBytes(StandardCharsets.UTF_8);

         // Encrypt with SunJCE
         Cipher sunCipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
         sunCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         sunCipher.updateAAD(aad);
         byte[] ciphertext = sunCipher.doFinal(plaintext);

         // Decrypt with GlaSSLess using ByteBuffer (the CipherSpi.bufferCrypt path)
         Cipher glassCipher = Cipher.getInstance("AES/GCM/NoPadding",
            GlaSSLessProvider.PROVIDER_NAME);
         glassCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         glassCipher.updateAAD(ByteBuffer.wrap(aad));
         ByteBuffer inputBuf = ByteBuffer.wrap(ciphertext);
         ByteBuffer outputBuf = ByteBuffer.allocate(
            glassCipher.getOutputSize(ciphertext.length));
         int produced = glassCipher.doFinal(inputBuf, outputBuf);

         byte[] decrypted = new byte[produced];
         outputBuf.flip();
         outputBuf.get(decrypted);
         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("Cross-provider AES-128-GCM (TLS_AES_128_GCM_SHA256)")
      void testCrossProviderAES128GCM() throws Exception {
         KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
         keyGen.init(128);
         SecretKey key = keyGen.generateKey();

         byte[] iv = new byte[12];
         new SecureRandom().nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         byte[] aad = {0x17, 0x03, 0x03, 0x00, 0x1A};
         byte[] plaintext = "AES-128 cross-provider".getBytes(StandardCharsets.UTF_8);

         // Encrypt with SunJCE
         Cipher sunCipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
         sunCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         sunCipher.updateAAD(aad);
         byte[] ciphertext = sunCipher.doFinal(plaintext);

         // Decrypt with GlaSSLess
         Cipher glassCipher = Cipher.getInstance("AES/GCM/NoPadding",
            GlaSSLessProvider.PROVIDER_NAME);
         glassCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
         glassCipher.updateAAD(aad);
         byte[] decrypted = glassCipher.doFinal(ciphertext);

         assertArrayEquals(plaintext, decrypted);
      }

      @Test
      @DisplayName("Multiple GCM encrypt/decrypt cycles (TLS record sequence)")
      void testMultipleGCMCycles() throws Exception {
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(256);
         SecretKey key = keyGen.generateKey();

         // Simulate multiple TLS records: each record uses a different nonce
         for (int i = 0; i < 10; i++) {
            byte[] iv = new byte[12];
            iv[11] = (byte) i; // Incrementing nonce like TLS 1.3
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            byte[] aad = {0x17, 0x03, 0x03, (byte) (i >> 8), (byte) i};
            byte[] plaintext = ("Record " + i + " payload data").getBytes(StandardCharsets.UTF_8);

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(plaintext);

            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            cipher.updateAAD(aad);
            byte[] decrypted = cipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted, "Record " + i + " decryption failed");
         }
      }
   }

   @Nested
   @DisplayName("Cross-provider HMAC/HKDF (TLS 1.3 key derivation)")
   class HMACHKDFTests {

      @Test
      @DisplayName("Cross-provider HMAC-SHA256")
      void testCrossProviderHmacSHA256() throws Exception {
         byte[] keyBytes = "test-hmac-key-for-cross-provider".getBytes(StandardCharsets.UTF_8);
         byte[] data = "TLS 1.3 handshake transcript hash".getBytes(StandardCharsets.UTF_8);
         SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");

         // SunJCE HMAC
         javax.crypto.Mac sunMac = javax.crypto.Mac.getInstance("HmacSHA256", "SunJCE");
         sunMac.init(key);
         byte[] sunResult = sunMac.doFinal(data);

         // GlaSSLess HMAC
         javax.crypto.Mac glassMac = javax.crypto.Mac.getInstance("HmacSHA256",
            GlaSSLessProvider.PROVIDER_NAME);
         glassMac.init(key);
         byte[] glassResult = glassMac.doFinal(data);

         assertArrayEquals(sunResult, glassResult,
            "HMAC-SHA256 must produce identical output across providers");
      }

      @Test
      @DisplayName("Cross-provider HMAC-SHA384")
      void testCrossProviderHmacSHA384() throws Exception {
         byte[] keyBytes = "test-hmac-key-for-cross-provider-384".getBytes(StandardCharsets.UTF_8);
         byte[] data = "TLS 1.3 handshake data".getBytes(StandardCharsets.UTF_8);
         SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA384");

         javax.crypto.Mac sunMac = javax.crypto.Mac.getInstance("HmacSHA384", "SunJCE");
         sunMac.init(key);
         byte[] sunResult = sunMac.doFinal(data);

         javax.crypto.Mac glassMac = javax.crypto.Mac.getInstance("HmacSHA384",
            GlaSSLessProvider.PROVIDER_NAME);
         glassMac.init(key);
         byte[] glassResult = glassMac.doFinal(data);

         assertArrayEquals(sunResult, glassResult);
      }

      @Test
      @DisplayName("Cross-provider HKDF-SHA256 (TLS 1.3 key schedule)")
      void testCrossProviderHKDF() throws Exception {
         // Simulate TLS 1.3 key derivation
         byte[] ikm = new byte[32];
         new SecureRandom().nextBytes(ikm);
         byte[] salt = new byte[32];
         byte[] info = "tls13 derived key".getBytes(StandardCharsets.UTF_8);

         // Derive with default provider (GlaSSLess at position 1)
         javax.crypto.KDF hkdf1 = javax.crypto.KDF.getInstance("HKDF-SHA256");
         javax.crypto.spec.HKDFParameterSpec params1 = javax.crypto.spec.HKDFParameterSpec
            .ofExtract().addIKM(ikm).addSalt(salt).thenExpand(info, 32);
         SecretKey key1 = hkdf1.deriveKey("AES", params1);

         // Derive with explicit GlaSSLess
         javax.crypto.KDF hkdf2 = javax.crypto.KDF.getInstance("HKDF-SHA256",
            GlaSSLessProvider.PROVIDER_NAME);
         javax.crypto.spec.HKDFParameterSpec params2 = javax.crypto.spec.HKDFParameterSpec
            .ofExtract().addIKM(ikm).addSalt(salt).thenExpand(info, 32);
         SecretKey key2 = hkdf2.deriveKey("AES", params2);

         assertArrayEquals(key1.getEncoded(), key2.getEncoded(),
            "HKDF must produce identical keys regardless of provider");
      }
   }

   @Nested
   @DisplayName("Full TLS 1.3 handshake with highest-priority GlaSSLess")
   class TLS13HandshakeTests {

      @Test
      @DisplayName("TLS 1.3 handshake + data exchange with ECDSA P-256")
      @Timeout(60)
      void testTLS13HandshakeECDSA() throws Exception {
         doTLSHandshakeTest("EC", 256, "SHA256withECDSA");
      }

      @Test
      @DisplayName("TLS 1.3 handshake + data exchange with RSA-2048")
      @Timeout(60)
      void testTLS13HandshakeRSA() throws Exception {
         doTLSHandshakeTest("RSA", 2048, "SHA256withRSA");
      }

      @Test
      @DisplayName("TLS 1.3 large data transfer (multiple GCM records)")
      @Timeout(120)
      void testTLS13LargeDataTransfer() throws Exception {
         java.security.KeyStore[] stores = generateKeyStore("EC", 256, "SHA256withECDSA");
         SSLContext serverCtx = createSSLContext(stores[0]);
         SSLContext clientCtx = createClientSSLContext(stores[1]);

         // 64KB — forces multiple TLS records (max record size is 16KB)
         byte[] largePayload = new byte[64 * 1024];
         new SecureRandom().nextBytes(largePayload);

         AtomicReference<Integer> port = new AtomicReference<>();
         CountDownLatch ready = new CountDownLatch(1);
         AtomicReference<Exception> error = new AtomicReference<>();
         AtomicReference<byte[]> received = new AtomicReference<>();

         Thread server = new Thread(() -> {
            try (SSLServerSocket ss = (SSLServerSocket) serverCtx
                  .getServerSocketFactory().createServerSocket(0)) {
               ss.setEnabledProtocols(new String[]{"TLSv1.3"});
               port.set(ss.getLocalPort());
               ready.countDown();

               try (SSLSocket sock = (SSLSocket) ss.accept()) {
                  InputStream in = sock.getInputStream();
                  OutputStream out = sock.getOutputStream();

                  byte[] data = in.readNBytes(largePayload.length);
                  received.set(data);

                  // Echo back a hash as ACK
                  java.security.MessageDigest md =
                     java.security.MessageDigest.getInstance("SHA-256");
                  out.write(md.digest(data));
                  out.flush();
               }
            } catch (Exception e) {
               error.set(e);
            }
         });
         server.start();

         assertTrue(ready.await(30, TimeUnit.SECONDS));

         try (SSLSocket client = (SSLSocket) clientCtx.getSocketFactory()
               .createSocket("localhost", port.get())) {
            client.setEnabledProtocols(new String[]{"TLSv1.3"});
            client.startHandshake();

            OutputStream out = client.getOutputStream();
            InputStream in = client.getInputStream();

            out.write(largePayload);
            out.flush();

            byte[] hash = in.readNBytes(32);
            java.security.MessageDigest md =
               java.security.MessageDigest.getInstance("SHA-256");
            assertArrayEquals(md.digest(largePayload), hash, "Data integrity failed");
         }

         server.join(30000);
         if (error.get() != null) {
            throw error.get();
         }
         assertArrayEquals(largePayload, received.get());
      }

      @ParameterizedTest(name = "TLS 1.3 with cipher suite {0}")
      @ValueSource(strings = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"})
      @Timeout(60)
      void testTLS13CipherSuites(String cipherSuite) throws Exception {
         java.security.KeyStore[] stores = generateKeyStore("EC", 256, "SHA256withECDSA");
         SSLContext serverCtx = createSSLContext(stores[0]);
         SSLContext clientCtx = createClientSSLContext(stores[1]);

         AtomicReference<Integer> port = new AtomicReference<>();
         CountDownLatch ready = new CountDownLatch(1);
         AtomicReference<Exception> error = new AtomicReference<>();
         AtomicReference<String> negotiated = new AtomicReference<>();

         Thread server = new Thread(() -> {
            try (SSLServerSocket ss = (SSLServerSocket) serverCtx
                  .getServerSocketFactory().createServerSocket(0)) {
               ss.setEnabledProtocols(new String[]{"TLSv1.3"});
               ss.setEnabledCipherSuites(new String[]{cipherSuite});
               port.set(ss.getLocalPort());
               ready.countDown();

               try (SSLSocket sock = (SSLSocket) ss.accept()) {
                  sock.startHandshake();
                  negotiated.set(sock.getSession().getCipherSuite());
                  InputStream in = sock.getInputStream();
                  OutputStream out = sock.getOutputStream();
                  byte[] buf = new byte[256];
                  int n = in.read(buf);
                  out.write(buf, 0, n);
                  out.flush();
               }
            } catch (Exception e) {
               error.set(e);
            }
         });
         server.start();

         assertTrue(ready.await(30, TimeUnit.SECONDS));

         try (SSLSocket client = (SSLSocket) clientCtx.getSocketFactory()
               .createSocket("localhost", port.get())) {
            client.setEnabledProtocols(new String[]{"TLSv1.3"});
            client.setEnabledCipherSuites(new String[]{cipherSuite});
            client.startHandshake();

            client.getOutputStream().write("ping".getBytes(StandardCharsets.UTF_8));
            client.getOutputStream().flush();
            byte[] resp = client.getInputStream().readNBytes(4);
            assertEquals("ping", new String(resp, StandardCharsets.UTF_8));
         }

         server.join(30000);
         if (error.get() != null) {
            throw error.get();
         }
         assertEquals(cipherSuite, negotiated.get());
      }
   }

   @Nested
   @DisplayName("TLS 1.3 with external OpenSSL server")
   class ExternalTLSTests {

      @Test
      @DisplayName("TLS 1.3 handshake with openssl s_server (simulates MySQL/external TLS)")
      @Timeout(30)
      void testTLS13WithOpenSSLServer() throws Exception {
         // Generate self-signed cert with openssl
         Path certPath = tempDir.resolve("cert.pem");
         Path keyPath = tempDir.resolve("key.pem");

         Process genCert = new ProcessBuilder(
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", keyPath.toString(),
            "-out", certPath.toString(),
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost"
         ).redirectErrorStream(true).start();
         assertEquals(0, genCert.waitFor(), "Failed to generate certificate");

         // Find a free port
         java.net.ServerSocket tempSocket = new java.net.ServerSocket(0);
         int port = tempSocket.getLocalPort();
         tempSocket.close();

         // Start openssl s_server
         Process server = new ProcessBuilder(
            "openssl", "s_server",
            "-cert", certPath.toString(),
            "-key", keyPath.toString(),
            "-accept", String.valueOf(port),
            "-tls1_3",
            "-www"  // Simple HTTP response mode
         ).redirectErrorStream(true).start();

         try {
            // Wait for server to start
            Thread.sleep(500);

            // Load the generated certificate as trust anchor
            java.security.cert.CertificateFactory cf =
               java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert;
            try (var fis = new java.io.FileInputStream(certPath.toFile())) {
               cert = cf.generateCertificate(fis);
            }

            java.security.KeyStore trustStore = java.security.KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("server", cert);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
               TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(null, tmf.getTrustManagers(), new SecureRandom());

            // Connect to the openssl s_server
            try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory()
                  .createSocket("localhost", port)) {
               socket.setEnabledProtocols(new String[]{"TLSv1.3"});
               socket.startHandshake();

               assertEquals("TLSv1.3", socket.getSession().getProtocol());

               // Send HTTP request and read response
               OutputStream out = socket.getOutputStream();
               out.write("GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
               out.flush();

               InputStream in = socket.getInputStream();
               byte[] buf = new byte[4096];
               int n = in.read(buf);
               assertTrue(n > 0, "Should receive response from openssl s_server");
               String response = new String(buf, 0, n, StandardCharsets.UTF_8);
               assertTrue(response.contains("HTTP"),
                  "Response should be HTTP, got: " + response.substring(0, Math.min(100, response.length())));
            }
         } finally {
            server.destroyForcibly();
            server.waitFor(5, TimeUnit.SECONDS);
         }
      }
   }

   // ── Helpers ──────────────────────────────────────────────────────────

   private void doTLSHandshakeTest(String keyAlg, int keySize, String sigAlg) throws Exception {
      java.security.KeyStore[] stores = generateKeyStore(keyAlg, keySize, sigAlg);
      SSLContext serverCtx = createSSLContext(stores[0]);
      SSLContext clientCtx = createClientSSLContext(stores[1]);

      AtomicReference<Integer> port = new AtomicReference<>();
      CountDownLatch ready = new CountDownLatch(1);
      AtomicReference<Exception> error = new AtomicReference<>();
      AtomicReference<String> received = new AtomicReference<>();

      Thread server = new Thread(() -> {
         try (SSLServerSocket ss = (SSLServerSocket) serverCtx
               .getServerSocketFactory().createServerSocket(0)) {
            ss.setEnabledProtocols(new String[]{"TLSv1.3"});
            port.set(ss.getLocalPort());
            ready.countDown();

            try (SSLSocket sock = (SSLSocket) ss.accept()) {
               sock.startHandshake();
               InputStream in = sock.getInputStream();
               OutputStream out = sock.getOutputStream();
               byte[] buf = new byte[256];
               int n = in.read(buf);
               received.set(new String(buf, 0, n, StandardCharsets.UTF_8));
               out.write(buf, 0, n);
               out.flush();
            }
         } catch (Exception e) {
            error.set(e);
         }
      });
      server.start();

      assertTrue(ready.await(30, TimeUnit.SECONDS));

      String echo;
      try (SSLSocket client = (SSLSocket) clientCtx.getSocketFactory()
            .createSocket("localhost", port.get())) {
         client.setEnabledProtocols(new String[]{"TLSv1.3"});
         client.startHandshake();

         String msg = "Hello from JSSE compat test!";
         client.getOutputStream().write(msg.getBytes(StandardCharsets.UTF_8));
         client.getOutputStream().flush();

         byte[] resp = client.getInputStream().readNBytes(msg.length());
         echo = new String(resp, StandardCharsets.UTF_8);
      }

      server.join(30000);
      if (error.get() != null) {
         throw error.get();
      }
      assertEquals("Hello from JSSE compat test!", received.get());
      assertEquals("Hello from JSSE compat test!", echo);
   }

   private java.security.KeyStore[] generateKeyStore(String keyAlg, int keySize, String sigAlg)
         throws Exception {
      Path ksPath = tempDir.resolve("ks-" + System.nanoTime() + ".p12");
      char[] password = "changeit".toCharArray();

      java.util.List<String> cmd = new java.util.ArrayList<>(java.util.List.of(
         "keytool", "-genkeypair", "-alias", "server", "-keyalg", keyAlg));

      if ("EC".equals(keyAlg)) {
         String curve = switch (keySize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported EC size: " + keySize);
         };
         cmd.addAll(java.util.List.of("-groupname", curve));
      } else {
         cmd.addAll(java.util.List.of("-keysize", String.valueOf(keySize)));
      }

      cmd.addAll(java.util.List.of(
         "-sigalg", sigAlg,
         "-validity", "1",
         "-keystore", ksPath.toString(),
         "-storepass", new String(password),
         "-keypass", new String(password),
         "-dname", "CN=localhost,O=Test,C=US",
         "-storetype", "PKCS12"));

      ProcessBuilder pb = new ProcessBuilder(cmd);
      pb.inheritIO();
      int exit = pb.start().waitFor();
      if (exit != 0) {
         throw new RuntimeException("keytool failed: " + exit);
      }

      // Temporarily remove GlaSSLess during PKCS12 load — the PKCS12 MAC verification
      // uses PBE/HMAC internally, which may not produce correct results through GlaSSLess
      Security.removeProvider(provider.getName());
      try {
         java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
         try (var fis = new java.io.FileInputStream(ksPath.toFile())) {
            ks.load(fis, password);
         }

         java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
         ts.load(null, password);
         ts.setCertificateEntry("server", ks.getCertificate("server"));

         return new java.security.KeyStore[]{ks, ts};
      } finally {
         Security.insertProviderAt(provider, 1);
      }
   }

   private SSLContext createSSLContext(java.security.KeyStore keyStore) throws Exception {
      char[] password = "changeit".toCharArray();
      // Temporarily remove GlaSSLess for KeyManagerFactory.init — it extracts the
      // private key from PKCS12, which internally uses PBE cipher
      Security.removeProvider(provider.getName());
      try {
         KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
         kmf.init(keyStore, password);

         TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
         tmf.init(keyStore);

         // Re-insert GlaSSLess BEFORE creating SSLContext so TLS operations use it
         Security.insertProviderAt(provider, 1);

         SSLContext ctx = SSLContext.getInstance("TLSv1.3");
         ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
         return ctx;
      } catch (Exception e) {
         // Ensure provider is re-inserted even on failure
         if (Security.getProvider(provider.getName()) == null) {
            Security.insertProviderAt(provider, 1);
         }
         throw e;
      }
   }

   private SSLContext createClientSSLContext(java.security.KeyStore trustStore) throws Exception {
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);

      SSLContext ctx = SSLContext.getInstance("TLSv1.3");
      ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
      return ctx;
   }
}
