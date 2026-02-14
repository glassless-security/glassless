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
 * <p>ML-KEM is currently only available in GlaSSLess (via OpenSSL 3.5+).
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

   private KeyPairGenerator glasslessKeyPairGen;
   private KEM glasslessKEM;
   private KeyPair keyPair;
   private KEM.Encapsulator encapsulator;
   private KEM.Decapsulator decapsulator;
   private byte[] encapsulation;
   private boolean available;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());

      // Check if ML-KEM is available (requires OpenSSL 3.5+)
      String opensslName = switch (algorithm) {
         case "ML-KEM-512" -> "mlkem512";
         case "ML-KEM-768" -> "mlkem768";
         case "ML-KEM-1024" -> "mlkem1024";
         default -> "mlkem768";
      };

      available = OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", opensslName);

      if (!available) {
         System.err.println("ML-KEM not available (requires OpenSSL 3.5+)");
         return;
      }

      glasslessKeyPairGen = KeyPairGenerator.getInstance(algorithm, "GlaSSLess");
      glasslessKEM = KEM.getInstance(algorithm, "GlaSSLess");

      // Pre-generate a key pair for encapsulation/decapsulation benchmarks
      keyPair = glasslessKeyPairGen.generateKeyPair();
      encapsulator = glasslessKEM.newEncapsulator(keyPair.getPublic());
      decapsulator = glasslessKEM.newDecapsulator(keyPair.getPrivate());

      // Pre-generate an encapsulation for decapsulation benchmark
      KEM.Encapsulated enc = encapsulator.encapsulate();
      encapsulation = enc.encapsulation();
   }

   @Benchmark
   public KeyPair glasslessKeyGen() {
      if (!available) {
         return null;
      }
      return glasslessKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public void glasslessEncapsulate(Blackhole bh) throws Exception {
      if (!available) {
         return;
      }
      KEM.Encapsulated result = encapsulator.encapsulate();
      bh.consume(result.key());
      bh.consume(result.encapsulation());
   }

   @Benchmark
   public SecretKey glasslessDecapsulate() throws Exception {
      if (!available) {
         return null;
      }
      return decapsulator.decapsulate(encapsulation);
   }
}
