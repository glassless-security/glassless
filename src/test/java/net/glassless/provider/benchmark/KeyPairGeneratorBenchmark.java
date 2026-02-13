package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

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

import net.glassless.provider.GlasslessProvider;

/**
 * JMH benchmarks comparing KeyPairGenerator performance between JDK and Glassless providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=KeyPairGeneratorBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class KeyPairGeneratorBenchmark {

   @Param({"EC-P256", "EC-P384", "RSA-2048", "RSA-4096", "Ed25519", "X25519"})
   private String algorithm;

   private KeyPairGenerator jdkKeyPairGen;
   private KeyPairGenerator glasslessKeyPairGen;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());

      if (algorithm.startsWith("EC-")) {
         String curve = algorithm.equals("EC-P256") ? "secp256r1" : "secp384r1";

         jdkKeyPairGen = KeyPairGenerator.getInstance("EC");
         jdkKeyPairGen.initialize(new ECGenParameterSpec(curve));

         glasslessKeyPairGen = KeyPairGenerator.getInstance("EC", "Glassless");
         glasslessKeyPairGen.initialize(new ECGenParameterSpec(curve));
      } else if (algorithm.startsWith("RSA-")) {
         int keySize = Integer.parseInt(algorithm.split("-")[1]);

         jdkKeyPairGen = KeyPairGenerator.getInstance("RSA");
         jdkKeyPairGen.initialize(keySize);

         glasslessKeyPairGen = KeyPairGenerator.getInstance("RSA", "Glassless");
         glasslessKeyPairGen.initialize(keySize);
      } else {
         jdkKeyPairGen = KeyPairGenerator.getInstance(algorithm);
         glasslessKeyPairGen = KeyPairGenerator.getInstance(algorithm, "Glassless");
      }
   }

   @Benchmark
   public KeyPair jdkGenerateKeyPair() {
      return jdkKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public KeyPair glasslessGenerateKeyPair() {
      return glasslessKeyPairGen.generateKeyPair();
   }
}
