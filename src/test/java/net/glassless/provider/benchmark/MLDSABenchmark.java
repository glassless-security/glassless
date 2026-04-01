package net.glassless.provider.benchmark;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
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

import net.glassless.provider.GlaSSLessProvider;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * JMH benchmarks for ML-DSA (FIPS 204) Digital Signature Algorithm.
 *
 * <p>Compares performance between GlaSSLess (via OpenSSL 3.5+) and JDK (27+) implementations.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=MLDSABenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class MLDSABenchmark {

   @Param({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
   private String algorithm;

   private static final byte[] DATA = new byte[256];

   // GlaSSLess components
   private KeyPairGenerator glasslessKeyPairGen;
   private Signature glasslessSignature;
   private Signature glasslessVerifySignature;
   private KeyPair glasslessKeyPair;
   private byte[] glasslessSignatureBytes;
   private boolean glasslessAvailable;

   // JDK components
   private KeyPairGenerator jdkKeyPairGen;
   private Signature jdkSignature;
   private Signature jdkVerifySignature;
   private KeyPair jdkKeyPair;
   private byte[] jdkSignatureBytes;
   private boolean jdkAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());

      String opensslName = algorithm.toLowerCase().replace("-", "");
      glasslessAvailable = OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", opensslName);

      if (glasslessAvailable) {
         glasslessKeyPairGen = KeyPairGenerator.getInstance(algorithm, PROVIDER_NAME);
         glasslessKeyPair = glasslessKeyPairGen.generateKeyPair();

         glasslessSignature = Signature.getInstance(algorithm, PROVIDER_NAME);
         glasslessSignature.initSign(glasslessKeyPair.getPrivate());
         glasslessSignature.update(DATA);
         glasslessSignatureBytes = glasslessSignature.sign();

         glasslessVerifySignature = Signature.getInstance(algorithm, PROVIDER_NAME);
      } else {
         System.err.println("GlaSSLess ML-DSA not available (requires OpenSSL 3.5+)");
      }

      // Setup JDK (requires JDK 27+)
      jdkAvailable = false;
      try {
         jdkKeyPairGen = KeyPairGenerator.getInstance(algorithm);
         jdkKeyPair = jdkKeyPairGen.generateKeyPair();

         jdkSignature = Signature.getInstance(algorithm);
         jdkSignature.initSign(jdkKeyPair.getPrivate());
         jdkSignature.update(DATA);
         jdkSignatureBytes = jdkSignature.sign();

         jdkVerifySignature = Signature.getInstance(algorithm);
         jdkAvailable = true;
      } catch (Exception e) {
         System.err.println("JDK ML-DSA not available (requires JDK 27+): " + e.getMessage());
      }
   }

   // GlaSSLess benchmarks

   @Benchmark
   public KeyPair glasslessKeyGen() {
      if (!glasslessAvailable) return null;
      return glasslessKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public byte[] glasslessSign() throws Exception {
      if (!glasslessAvailable) return null;
      glasslessSignature.initSign(glasslessKeyPair.getPrivate());
      glasslessSignature.update(DATA);
      return glasslessSignature.sign();
   }

   @Benchmark
   public boolean glasslessVerify() throws Exception {
      if (!glasslessAvailable) return false;
      glasslessVerifySignature.initVerify(glasslessKeyPair.getPublic());
      glasslessVerifySignature.update(DATA);
      return glasslessVerifySignature.verify(glasslessSignatureBytes);
   }

   // JDK benchmarks

   @Benchmark
   public KeyPair jdkKeyGen() {
      if (!jdkAvailable) return null;
      return jdkKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public byte[] jdkSign() throws Exception {
      if (!jdkAvailable) return null;
      jdkSignature.initSign(jdkKeyPair.getPrivate());
      jdkSignature.update(DATA);
      return jdkSignature.sign();
   }

   @Benchmark
   public boolean jdkVerify() throws Exception {
      if (!jdkAvailable) return false;
      jdkVerifySignature.initVerify(jdkKeyPair.getPublic());
      jdkVerifySignature.update(DATA);
      return jdkVerifySignature.verify(jdkSignatureBytes);
   }
}
