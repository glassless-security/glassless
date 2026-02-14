package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import net.glassless.provider.GlaSSLessProvider;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * JMH benchmarks for ML-KEM (FIPS 203) Key Encapsulation Mechanism.
 *
 * <p>Compares performance between GlaSSLess (via OpenSSL 3.5+) and JDK (24+) implementations.
 * This benchmark measures key generation, encapsulation, and decapsulation performance.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=KEMBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class KEMBenchmark {

   @Param({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
   private String algorithm;

   // GlaSSLess components
   private KeyPairGenerator glasslessKeyPairGen;
   private KEM glasslessKEM;
   private KeyPair glasslessKeyPair;
   private KEM.Encapsulator glasslessEncapsulator;
   private KEM.Decapsulator glasslessDecapsulator;
   private byte[] glasslessEncapsulation;
   private boolean glasslessAvailable;

   // JDK components
   private KeyPairGenerator jdkKeyPairGen;
   private KEM jdkKEM;
   private KeyPair jdkKeyPair;
   private KEM.Encapsulator jdkEncapsulator;
   private KEM.Decapsulator jdkDecapsulator;
   private byte[] jdkEncapsulation;
   private boolean jdkAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());

      // Setup GlaSSLess (requires OpenSSL 3.5+)
      String opensslName = switch (algorithm) {
         case "ML-KEM-512" -> "mlkem512";
         case "ML-KEM-768" -> "mlkem768";
         case "ML-KEM-1024" -> "mlkem1024";
         default -> "mlkem768";
      };

      glasslessAvailable = OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", opensslName);

      if (glasslessAvailable) {
         glasslessKeyPairGen = KeyPairGenerator.getInstance(algorithm, "GlaSSLess");
         glasslessKEM = KEM.getInstance(algorithm, "GlaSSLess");

         // Pre-generate a key pair for encapsulation/decapsulation benchmarks
         glasslessKeyPair = glasslessKeyPairGen.generateKeyPair();
         glasslessEncapsulator = glasslessKEM.newEncapsulator(glasslessKeyPair.getPublic());
         glasslessDecapsulator = glasslessKEM.newDecapsulator(glasslessKeyPair.getPrivate());

         // Pre-generate an encapsulation for decapsulation benchmark
         KEM.Encapsulated enc = glasslessEncapsulator.encapsulate();
         glasslessEncapsulation = enc.encapsulation();
      } else {
         System.err.println("GlaSSLess ML-KEM not available (requires OpenSSL 3.5+)");
      }

      // Setup JDK (requires JDK 24+)
      jdkAvailable = false;
      try {
         // Try to get ML-KEM from the default JDK provider
         jdkKeyPairGen = KeyPairGenerator.getInstance(algorithm);
         jdkKEM = KEM.getInstance(algorithm);

         // Pre-generate a key pair for encapsulation/decapsulation benchmarks
         jdkKeyPair = jdkKeyPairGen.generateKeyPair();
         jdkEncapsulator = jdkKEM.newEncapsulator(jdkKeyPair.getPublic());
         jdkDecapsulator = jdkKEM.newDecapsulator(jdkKeyPair.getPrivate());

         // Pre-generate an encapsulation for decapsulation benchmark
         KEM.Encapsulated enc = jdkEncapsulator.encapsulate();
         jdkEncapsulation = enc.encapsulation();

         jdkAvailable = true;
      } catch (Exception e) {
         System.err.println("JDK ML-KEM not available (requires JDK 24+): " + e.getMessage());
      }
   }

   // GlaSSLess benchmarks

   @Benchmark
   public KeyPair glasslessKeyGen() {
      if (!glasslessAvailable) {
         return null;
      }
      return glasslessKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public void glasslessEncapsulate(Blackhole bh) throws Exception {
      if (!glasslessAvailable) {
         return;
      }
      KEM.Encapsulated result = glasslessEncapsulator.encapsulate();
      bh.consume(result.key());
      bh.consume(result.encapsulation());
   }

   @Benchmark
   public SecretKey glasslessDecapsulate() throws Exception {
      if (!glasslessAvailable) {
         return null;
      }
      return glasslessDecapsulator.decapsulate(glasslessEncapsulation);
   }

   // JDK benchmarks

   @Benchmark
   public KeyPair jdkKeyGen() {
      if (!jdkAvailable) {
         return null;
      }
      return jdkKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public void jdkEncapsulate(Blackhole bh) throws Exception {
      if (!jdkAvailable) {
         return;
      }
      KEM.Encapsulated result = jdkEncapsulator.encapsulate();
      bh.consume(result.key());
      bh.consume(result.encapsulation());
   }

   @Benchmark
   public SecretKey jdkDecapsulate() throws Exception {
      if (!jdkAvailable) {
         return null;
      }
      return jdkDecapsulator.decapsulate(jdkEncapsulation);
   }
}
