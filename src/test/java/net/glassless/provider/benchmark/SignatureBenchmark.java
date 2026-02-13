package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
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
 * JMH benchmarks comparing Signature performance between JDK and Glassless providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=SignatureBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class SignatureBenchmark {

   @Param({"SHA256withECDSA", "SHA384withECDSA", "Ed25519"})
   private String algorithm;

   private byte[] data;
   private byte[] jdkSignature;
   private byte[] glasslessSignature;
   private KeyPair keyPair;
   private Signature jdkSigner;
   private Signature jdkVerifier;
   private Signature glasslessSigner;
   private Signature glasslessVerifier;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());

      data = "This is the data to be signed for benchmark testing purposes.".getBytes();

      if (algorithm.equals("Ed25519")) {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
         keyPair = kpg.generateKeyPair();
      } else {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
         String curve = algorithm.contains("384") ? "secp384r1" : "secp256r1";
         kpg.initialize(new ECGenParameterSpec(curve));
         keyPair = kpg.generateKeyPair();
      }

      // JDK signer/verifier
      jdkSigner = Signature.getInstance(algorithm);
      jdkSigner.initSign(keyPair.getPrivate());

      jdkVerifier = Signature.getInstance(algorithm);
      jdkVerifier.initVerify(keyPair.getPublic());

      // Glassless signer/verifier
      glasslessSigner = Signature.getInstance(algorithm, "Glassless");
      glasslessSigner.initSign(keyPair.getPrivate());

      glasslessVerifier = Signature.getInstance(algorithm, "Glassless");
      glasslessVerifier.initVerify(keyPair.getPublic());

      // Pre-compute signatures for verify benchmarks
      jdkSigner.update(data);
      jdkSignature = jdkSigner.sign();

      glasslessSigner.update(data);
      glasslessSignature = glasslessSigner.sign();
   }

   @Benchmark
   public byte[] jdkSign() throws Exception {
      jdkSigner.update(data);
      return jdkSigner.sign();
   }

   @Benchmark
   public byte[] glasslessSign() throws Exception {
      glasslessSigner.update(data);
      return glasslessSigner.sign();
   }

   @Benchmark
   public boolean jdkVerify() throws Exception {
      jdkVerifier.initVerify(keyPair.getPublic());
      jdkVerifier.update(data);
      return jdkVerifier.verify(jdkSignature);
   }

   @Benchmark
   public boolean glasslessVerify() throws Exception {
      glasslessVerifier.initVerify(keyPair.getPublic());
      glasslessVerifier.update(data);
      return glasslessVerifier.verify(glasslessSignature);
   }
}
