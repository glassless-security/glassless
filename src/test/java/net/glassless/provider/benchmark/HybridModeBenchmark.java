package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.concurrent.TimeUnit;

import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import net.glassless.provider.GlaSSLessProvider;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * JMH benchmarks demonstrating hybrid mode performance benefits.
 *
 * <p>This benchmark compares three configurations:
 * <ul>
 *   <li><b>JDK</b>: Pure JDK provider (no GlaSSLess)</li>
 *   <li><b>GlaSSLess</b>: GlaSSLess at highest priority (non-hybrid)</li>
 *   <li><b>Hybrid</b>: GlaSSLess with hybrid mode - gets best of both worlds</li>
 * </ul>
 *
 * <p>The benchmark shows that hybrid mode provides optimal performance by:
 * <ul>
 *   <li>Delegating SHA-256, HMAC-SHA256, SecureRandom to JDK (where JDK excels)</li>
 *   <li>Using GlaSSLess for ECDH, EdDSA, EC key generation (where OpenSSL excels)</li>
 * </ul>
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=HybridModeBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class HybridModeBenchmark {

   // Data for digest/MAC operations
   private static final int SMALL_DATA_SIZE = 64;
   private static final int SMALL_RANDOM_SIZE = 32;
   private byte[] smallData;

   // === JDK-optimized operations (JDK is faster) ===
   // JDK instances
   private MessageDigest jdkSha256;
   private Mac jdkHmacSha256;
   private SecureRandom jdkSecureRandom;
   private byte[] jdkRandomBuffer;

   // GlaSSLess instances (for comparison)
   private MessageDigest glasslessSha256;
   private Mac glasslessHmacSha256;
   private SecureRandom glasslessSecureRandom;
   private byte[] glasslessRandomBuffer;

   // === GlaSSLess-optimized operations (OpenSSL is faster) ===
   // JDK instances
   private KeyAgreement jdkEcdh;
   private KeyPair jdkEcKeyPair;
   private Signature jdkEd25519;
   private KeyPair jdkEd25519KeyPair;
   private KeyPairGenerator jdkEcKeyPairGen;

   // GlaSSLess instances
   private KeyAgreement glasslessEcdh;
   private KeyPair glasslessEcKeyPair;
   private Signature glasslessEd25519;
   private KeyPair glasslessEd25519KeyPair;
   private KeyPairGenerator glasslessEcKeyPairGen;

   // ML-KEM (JDK is faster in JDK 24+)
   private KEM jdkMlKem;
   private KEM.Encapsulator jdkMlKemEncapsulator;
   private KEM glasslessMlKem;
   private KEM.Encapsulator glasslessMlKemEncapsulator;
   private boolean mlKemAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      // Add GlaSSLess provider at low priority for explicit selection
      Security.addProvider(new GlaSSLessProvider());

      // Initialize test data
      smallData = new byte[SMALL_DATA_SIZE];
      for (int i = 0; i < smallData.length; i++) {
         smallData[i] = (byte) i;
      }
      jdkRandomBuffer = new byte[SMALL_RANDOM_SIZE];
      glasslessRandomBuffer = new byte[SMALL_RANDOM_SIZE];

      // === Setup JDK-optimized operations ===

      // MessageDigest - JDK excels at small data
      jdkSha256 = MessageDigest.getInstance("SHA-256");
      glasslessSha256 = MessageDigest.getInstance("SHA-256", "GlaSSLess");

      // Mac - JDK excels at small data
      byte[] keyBytes = new byte[32];
      new SecureRandom().nextBytes(keyBytes);
      SecretKeySpec hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");

      jdkHmacSha256 = Mac.getInstance("HmacSHA256");
      jdkHmacSha256.init(hmacKey);
      glasslessHmacSha256 = Mac.getInstance("HmacSHA256", "GlaSSLess");
      glasslessHmacSha256.init(hmacKey);

      // SecureRandom - JDK excels at small buffers
      jdkSecureRandom = SecureRandom.getInstance("NativePRNG");
      glasslessSecureRandom = SecureRandom.getInstance("NativePRNG", "GlaSSLess");

      // === Setup GlaSSLess-optimized operations ===

      // ECDH Key Agreement - GlaSSLess is ~6x faster
      jdkEcKeyPairGen = KeyPairGenerator.getInstance("EC");
      jdkEcKeyPairGen.initialize(256);
      jdkEcKeyPair = jdkEcKeyPairGen.generateKeyPair();
      jdkEcdh = KeyAgreement.getInstance("ECDH");
      jdkEcdh.init(jdkEcKeyPair.getPrivate());

      glasslessEcKeyPairGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
      glasslessEcKeyPairGen.initialize(256);
      glasslessEcKeyPair = glasslessEcKeyPairGen.generateKeyPair();
      glasslessEcdh = KeyAgreement.getInstance("ECDH", "GlaSSLess");
      glasslessEcdh.init(glasslessEcKeyPair.getPrivate());

      // Ed25519 Signature - GlaSSLess is ~8x faster
      KeyPairGenerator jdkEd25519Gen = KeyPairGenerator.getInstance("Ed25519");
      jdkEd25519KeyPair = jdkEd25519Gen.generateKeyPair();
      jdkEd25519 = Signature.getInstance("Ed25519");
      jdkEd25519.initSign(jdkEd25519KeyPair.getPrivate());

      KeyPairGenerator glasslessEd25519Gen = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
      glasslessEd25519KeyPair = glasslessEd25519Gen.generateKeyPair();
      glasslessEd25519 = Signature.getInstance("Ed25519", "GlaSSLess");
      glasslessEd25519.initSign(glasslessEd25519KeyPair.getPrivate());

      // ML-KEM - JDK is faster (if available)
      mlKemAvailable = false;
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem768")) {
         try {
            KeyPairGenerator jdkMlKemGen = KeyPairGenerator.getInstance("ML-KEM-768");
            KeyPair jdkMlKemKeyPair = jdkMlKemGen.generateKeyPair();
            jdkMlKem = KEM.getInstance("ML-KEM-768");
            jdkMlKemEncapsulator = jdkMlKem.newEncapsulator(jdkMlKemKeyPair.getPublic());

            KeyPairGenerator glasslessMlKemGen = KeyPairGenerator.getInstance("ML-KEM-768", "GlaSSLess");
            KeyPair glasslessMlKemKeyPair = glasslessMlKemGen.generateKeyPair();
            glasslessMlKem = KEM.getInstance("ML-KEM-768", "GlaSSLess");
            glasslessMlKemEncapsulator = glasslessMlKem.newEncapsulator(glasslessMlKemKeyPair.getPublic());

            mlKemAvailable = true;
         } catch (Exception e) {
            System.err.println("ML-KEM not available: " + e.getMessage());
         }
      }
   }

   // ============================================================
   // JDK-OPTIMIZED OPERATIONS (JDK is faster for small data)
   // In hybrid mode, these delegate to JDK
   // ============================================================

   @Benchmark
   public byte[] sha256_jdk() {
      return jdkSha256.digest(smallData);
   }

   @Benchmark
   public byte[] sha256_glassless() {
      return glasslessSha256.digest(smallData);
   }

   @Benchmark
   public byte[] hmacSha256_jdk() {
      return jdkHmacSha256.doFinal(smallData);
   }

   @Benchmark
   public byte[] hmacSha256_glassless() {
      return glasslessHmacSha256.doFinal(smallData);
   }

   @Benchmark
   public byte[] secureRandom_jdk() {
      jdkSecureRandom.nextBytes(jdkRandomBuffer);
      return jdkRandomBuffer;
   }

   @Benchmark
   public byte[] secureRandom_glassless() {
      glasslessSecureRandom.nextBytes(glasslessRandomBuffer);
      return glasslessRandomBuffer;
   }

   // ============================================================
   // GLASSLESS-OPTIMIZED OPERATIONS (OpenSSL is faster)
   // In hybrid mode, these still use GlaSSLess
   // ============================================================

   @Benchmark
   public byte[] ecdh_jdk() throws Exception {
      KeyPair peerKeyPair = jdkEcKeyPairGen.generateKeyPair();
      jdkEcdh.doPhase(peerKeyPair.getPublic(), true);
      return jdkEcdh.generateSecret();
   }

   @Benchmark
   public byte[] ecdh_glassless() throws Exception {
      KeyPair peerKeyPair = glasslessEcKeyPairGen.generateKeyPair();
      glasslessEcdh.doPhase(peerKeyPair.getPublic(), true);
      return glasslessEcdh.generateSecret();
   }

   @Benchmark
   public byte[] ed25519Sign_jdk() throws Exception {
      jdkEd25519.update(smallData);
      return jdkEd25519.sign();
   }

   @Benchmark
   public byte[] ed25519Sign_glassless() throws Exception {
      glasslessEd25519.update(smallData);
      return glasslessEd25519.sign();
   }

   @Benchmark
   public KeyPair ecKeyGen_jdk() {
      return jdkEcKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public KeyPair ecKeyGen_glassless() {
      return glasslessEcKeyPairGen.generateKeyPair();
   }

   // ============================================================
   // ML-KEM OPERATIONS (JDK is faster)
   // In hybrid mode, these delegate to JDK
   // ============================================================

   @Benchmark
   public void mlKemEncaps_jdk(Blackhole bh) throws Exception {
      if (!mlKemAvailable) {
         return;
      }
      KEM.Encapsulated result = jdkMlKemEncapsulator.encapsulate();
      bh.consume(result.key());
      bh.consume(result.encapsulation());
   }

   @Benchmark
   public void mlKemEncaps_glassless(Blackhole bh) throws Exception {
      if (!mlKemAvailable) {
         return;
      }
      KEM.Encapsulated result = glasslessMlKemEncapsulator.encapsulate();
      bh.consume(result.key());
      bh.consume(result.encapsulation());
   }

   // ============================================================
   // MIXED WORKLOAD - Simulates real-world usage
   // Shows combined benefit of hybrid mode
   // ============================================================

   /**
    * Mixed workload using JDK for everything.
    * This is the baseline - pure JDK performance.
    */
   @Benchmark
   public void mixedWorkload_jdk(Blackhole bh) throws Exception {
      // JDK-optimized: SHA-256 digest
      bh.consume(jdkSha256.digest(smallData));

      // JDK-optimized: HMAC
      bh.consume(jdkHmacSha256.doFinal(smallData));

      // GlaSSLess-optimized but using JDK: Ed25519 sign
      jdkEd25519.update(smallData);
      bh.consume(jdkEd25519.sign());
   }

   /**
    * Mixed workload using GlaSSLess for everything.
    * Shows penalty for using GlaSSLess on JDK-optimized operations.
    */
   @Benchmark
   public void mixedWorkload_glassless(Blackhole bh) throws Exception {
      // JDK-optimized but using GlaSSLess (slower)
      bh.consume(glasslessSha256.digest(smallData));

      // JDK-optimized but using GlaSSLess (slower)
      bh.consume(glasslessHmacSha256.doFinal(smallData));

      // GlaSSLess-optimized using GlaSSLess (faster)
      glasslessEd25519.update(smallData);
      bh.consume(glasslessEd25519.sign());
   }

   /**
    * Mixed workload using hybrid mode strategy.
    * Uses JDK for JDK-optimized ops, GlaSSLess for OpenSSL-optimized ops.
    * This should give the best overall performance.
    */
   @Benchmark
   public void mixedWorkload_hybrid(Blackhole bh) throws Exception {
      // JDK-optimized: use JDK (fast)
      bh.consume(jdkSha256.digest(smallData));

      // JDK-optimized: use JDK (fast)
      bh.consume(jdkHmacSha256.doFinal(smallData));

      // GlaSSLess-optimized: use GlaSSLess (fast)
      glasslessEd25519.update(smallData);
      bh.consume(glasslessEd25519.sign());
   }
}
