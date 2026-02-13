package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
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
 * JMH benchmarks comparing Signature performance between JDK, Glassless, BC FIPS, and NSS providers.
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

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   @Param({"SHA256withECDSA", "SHA384withECDSA"})
   private String algorithm;

   private byte[] data;
   private byte[] jdkSignature;
   private byte[] glasslessSignature;
   private byte[] bcFipsSignature;
   private byte[] nssSignature;
   private KeyPair keyPair;
   private Signature jdkSigner;
   private Signature jdkVerifier;
   private Signature glasslessSigner;
   private Signature glasslessVerifier;
   private Signature bcFipsSigner;
   private Signature bcFipsVerifier;
   private Signature nssSigner;
   private Signature nssVerifier;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      data = "This is the data to be signed for benchmark testing purposes.".getBytes();

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      String curve = algorithm.contains("384") ? "secp384r1" : "secp256r1";
      kpg.initialize(new ECGenParameterSpec(curve));
      keyPair = kpg.generateKeyPair();

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

      // BC FIPS signer/verifier
      bcFipsSigner = Signature.getInstance(algorithm, "BCFIPS");
      bcFipsSigner.initSign(keyPair.getPrivate());

      bcFipsVerifier = Signature.getInstance(algorithm, "BCFIPS");
      bcFipsVerifier.initVerify(keyPair.getPublic());

      // Try to configure NSS provider
      nssAvailable = false;
      try {
         Provider nssProvider = Security.getProvider("SunPKCS11");
         if (nssProvider != null) {
            Provider configuredNss = nssProvider.configure(NSS_CONFIG);
            Security.addProvider(configuredNss);

            nssSigner = Signature.getInstance(algorithm, configuredNss);
            nssSigner.initSign(keyPair.getPrivate());

            nssVerifier = Signature.getInstance(algorithm, configuredNss);
            nssVerifier.initVerify(keyPair.getPublic());

            nssSigner.update(data);
            nssSignature = nssSigner.sign();
            nssAvailable = true;
         }
      } catch (Exception e) {
         System.err.println("NSS provider not available for Signature: " + e.getMessage());
      }

      // Pre-compute signatures for verify benchmarks
      jdkSigner.update(data);
      jdkSignature = jdkSigner.sign();

      glasslessSigner.update(data);
      glasslessSignature = glasslessSigner.sign();

      bcFipsSigner.update(data);
      bcFipsSignature = bcFipsSigner.sign();
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
   public byte[] bcFipsSign() throws Exception {
      bcFipsSigner.update(data);
      return bcFipsSigner.sign();
   }

   @Benchmark
   public byte[] nssSign() throws Exception {
      if (!nssAvailable) {
         return data;
      }
      nssSigner.update(data);
      return nssSigner.sign();
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

   @Benchmark
   public boolean bcFipsVerify() throws Exception {
      bcFipsVerifier.initVerify(keyPair.getPublic());
      bcFipsVerifier.update(data);
      return bcFipsVerifier.verify(bcFipsSignature);
   }

   @Benchmark
   public boolean nssVerify() throws Exception {
      if (!nssAvailable) {
         return true;
      }
      nssVerifier.initVerify(keyPair.getPublic());
      nssVerifier.update(data);
      return nssVerifier.verify(nssSignature);
   }
}
