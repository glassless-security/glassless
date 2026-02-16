package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Soak tests to verify native memory is not leaked.
 * These tests create many cryptographic objects and verify that memory usage
 * stabilizes after garbage collection.
 */
public class NativeMemorySoakTest {

   private static final int WARMUP_ITERATIONS = 100;
   private static final int SOAK_ITERATIONS = 5000;
   private static final int GC_INTERVAL = 500;
   private static final byte[] TEST_DATA = new byte[1024];
   private static final SecureRandom RANDOM = new SecureRandom();

   // Max allowed memory growth in KB (10 MB)
   private static final long MAX_MEMORY_GROWTH_KB = 10240;

   @BeforeAll
   static void setup() {
      Security.insertProviderAt(new GlaSSLessProvider(), 1);
      RANDOM.nextBytes(TEST_DATA);
   }

   /**
    * Gets the resident set size (RSS) of the current process in KB.
    * This represents actual physical memory used, including native allocations.
    */
   private static long getResidentMemoryKB() {
      try {
         // Read from /proc/self/status which works without knowing PID
         try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
               if (line.startsWith("VmRSS:")) {
                  String[] parts = line.split("\\s+");
                  return Long.parseLong(parts[1]);
               }
            }
         }
      } catch (Exception e) {
         // Fall back to heap memory if /proc is not available
         Runtime runtime = Runtime.getRuntime();
         return (runtime.totalMemory() - runtime.freeMemory()) / 1024;
      }
      return -1;
   }

   private static void forceGC() {
      System.gc();
      System.runFinalization();
      try {
         Thread.sleep(100);
      } catch (InterruptedException e) {
         Thread.currentThread().interrupt();
      }
      System.gc();
   }

   @Nested
   @DisplayName("MessageDigest Soak Tests")
   class MessageDigestSoakTests {

      @Test
      @DisplayName("SHA-256 digest should not leak memory")
      void testSHA256NoLeak() throws Exception {
         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "GlaSSLess");
            md.update(TEST_DATA);
            md.digest();
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("MessageDigest baseline memory: " + baselineMemory + " KB");

         // Soak test
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "GlaSSLess");
            md.update(TEST_DATA);
            md.digest();

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("MessageDigest final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("MessageDigest memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak");
      }

      @Test
      @DisplayName("Multiple digest algorithms should not leak memory")
      void testMultipleDigestsNoLeak() throws Exception {
         String[] algorithms = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256"};

         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            for (String algo : algorithms) {
               MessageDigest md = MessageDigest.getInstance(algo, "GlaSSLess");
               md.update(TEST_DATA);
               md.digest();
            }
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("MultiDigest baseline memory: " + baselineMemory + " KB");

         // Soak test
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            for (String algo : algorithms) {
               MessageDigest md = MessageDigest.getInstance(algo, "GlaSSLess");
               md.update(TEST_DATA);
               md.digest();
            }

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("MultiDigest final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("MultiDigest memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak");
      }

      @Test
      @DisplayName("Abandoned digest (no digest() call) should not leak memory")
      void testAbandonedDigestNoLeak() throws Exception {
         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "GlaSSLess");
            md.update(TEST_DATA);
            // Intentionally not calling digest() - simulates abandoned object
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("AbandonedDigest baseline memory: " + baselineMemory + " KB");

         // Soak test - create and abandon digests
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "GlaSSLess");
            md.update(TEST_DATA);
            // Intentionally not calling digest()

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("AbandonedDigest final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("AbandonedDigest memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak in abandoned digests");
      }
   }

   @Nested
   @DisplayName("Cipher Soak Tests")
   class CipherSoakTests {

      private SecretKey aesKey;
      private boolean cipherAvailable;

      void setupCipher() {
         try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "GlaSSLess");
            keyGen.init(256);
            aesKey = keyGen.generateKey();
            // Check if cipher is available
            Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
            cipherAvailable = true;
         } catch (Exception e) {
            cipherAvailable = false;
         }
      }

      @Test
      @DisplayName("AES-GCM cipher should not leak memory")
      void testAESGCMNoLeak() throws Exception {
         setupCipher();
         assumeTrue(cipherAvailable, "AES_256/GCM/NoPadding not available");

         byte[] iv = new byte[12];
         RANDOM.nextBytes(iv);

         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.doFinal(TEST_DATA);
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("AES-GCM baseline memory: " + baselineMemory + " KB");

         // Soak test
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.doFinal(TEST_DATA);

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("AES-GCM final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("AES-GCM memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak");
      }

      @Test
      @DisplayName("Abandoned cipher (no doFinal) should not leak memory")
      void testAbandonedCipherNoLeak() throws Exception {
         setupCipher();
         assumeTrue(cipherAvailable, "AES_256/GCM/NoPadding not available");

         byte[] iv = new byte[12];
         RANDOM.nextBytes(iv);

         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.update(TEST_DATA);
            // Intentionally not calling doFinal()
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("AbandonedCipher baseline memory: " + baselineMemory + " KB");

         // Soak test
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.update(TEST_DATA);
            // Intentionally not calling doFinal()

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("AbandonedCipher final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("AbandonedCipher memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak in abandoned ciphers");
      }

      @Test
      @DisplayName("Cipher reinitialization should not leak memory")
      void testCipherReinitNoLeak() throws Exception {
         setupCipher();
         assumeTrue(cipherAvailable, "AES_256/GCM/NoPadding not available");

         byte[] iv = new byte[12];

         // Warmup
         Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            RANDOM.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.doFinal(TEST_DATA);
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("CipherReinit baseline memory: " + baselineMemory + " KB");

         // Soak test - reuse same cipher object
         cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            RANDOM.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.doFinal(TEST_DATA);

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("CipherReinit final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("CipherReinit memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak in cipher reinitialization");
      }
   }

   @Nested
   @DisplayName("Signature Soak Tests")
   class SignatureSoakTests {

      private KeyPair ecKeyPair;
      private boolean signatureAvailable;

      void setupSignature() {
         try {
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            ecKeyGen.initialize(256);
            ecKeyPair = ecKeyGen.generateKeyPair();
            signatureAvailable = true;
         } catch (Exception e) {
            signatureAvailable = false;
         }
      }

      @Test
      @DisplayName("ECDSA signature should not leak memory")
      void testECDSASignatureNoLeak() throws Exception {
         setupSignature();
         assumeTrue(signatureAvailable, "EC key generation not available");

         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(TEST_DATA);
            byte[] signature = sig.sign();

            sig.initVerify(ecKeyPair.getPublic());
            sig.update(TEST_DATA);
            sig.verify(signature);
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("ECDSASignature baseline memory: " + baselineMemory + " KB");

         // Soak test
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(TEST_DATA);
            byte[] signature = sig.sign();

            sig.initVerify(ecKeyPair.getPublic());
            sig.update(TEST_DATA);
            sig.verify(signature);

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("ECDSASignature final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("ECDSASignature memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak");
      }

      @Test
      @DisplayName("Abandoned signature (no sign/verify) should not leak memory")
      void testAbandonedSignatureNoLeak() throws Exception {
         setupSignature();
         assumeTrue(signatureAvailable, "EC key generation not available");

         // Warmup
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(TEST_DATA);
            // Intentionally not calling sign()
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("AbandonedSignature baseline memory: " + baselineMemory + " KB");

         // Soak test
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(TEST_DATA);
            // Intentionally not calling sign()

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("AbandonedSignature final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("AbandonedSignature memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak in abandoned signatures");
      }

      @Test
      @DisplayName("Signature reinitialization should not leak memory")
      void testSignatureReinitNoLeak() throws Exception {
         setupSignature();
         assumeTrue(signatureAvailable, "EC key generation not available");

         // Warmup
         Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
         for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(TEST_DATA);
            sig.sign();
         }

         forceGC();
         long baselineMemory = getResidentMemoryKB();
         System.out.println("SignatureReinit baseline memory: " + baselineMemory + " KB");

         // Soak test - reuse same signature object
         sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
         for (int i = 0; i < SOAK_ITERATIONS; i++) {
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(TEST_DATA);
            sig.sign();

            if (i % GC_INTERVAL == 0) {
               forceGC();
            }
         }

         forceGC();
         long finalMemory = getResidentMemoryKB();
         System.out.println("SignatureReinit final memory: " + finalMemory + " KB");

         long memoryGrowth = finalMemory - baselineMemory;
         System.out.println("SignatureReinit memory growth: " + memoryGrowth + " KB");

         assertTrue(memoryGrowth < MAX_MEMORY_GROWTH_KB,
            "Memory grew by " + memoryGrowth + " KB, possible leak in signature reinitialization");
      }
   }
}
