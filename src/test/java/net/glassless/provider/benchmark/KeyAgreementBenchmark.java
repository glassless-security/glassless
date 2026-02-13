package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyAgreement;

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
 * JMH benchmarks comparing KeyAgreement performance between JDK and Glassless providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=KeyAgreementBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class KeyAgreementBenchmark {

   @Param({"ECDH", "X25519"})
   private String algorithm;

   private KeyPair aliceKeyPair;
   private KeyPair bobKeyPair;
   private KeyAgreement jdkKeyAgreement;
   private KeyAgreement glasslessKeyAgreement;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());

      if (algorithm.equals("ECDH")) {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
         kpg.initialize(new ECGenParameterSpec("secp256r1"));
         aliceKeyPair = kpg.generateKeyPair();
         bobKeyPair = kpg.generateKeyPair();
      } else {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
         aliceKeyPair = kpg.generateKeyPair();
         bobKeyPair = kpg.generateKeyPair();
      }

      jdkKeyAgreement = KeyAgreement.getInstance(algorithm);
      glasslessKeyAgreement = KeyAgreement.getInstance(algorithm, "Glassless");
   }

   @Benchmark
   public byte[] jdkKeyAgreement() throws Exception {
      jdkKeyAgreement.init(aliceKeyPair.getPrivate());
      jdkKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
      return jdkKeyAgreement.generateSecret();
   }

   @Benchmark
   public byte[] glasslessKeyAgreement() throws Exception {
      glasslessKeyAgreement.init(aliceKeyPair.getPrivate());
      glasslessKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
      return glasslessKeyAgreement.generateSecret();
   }
}
