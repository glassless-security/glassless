package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyAgreement;

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
 * JMH benchmarks comparing KeyAgreement performance between JDK, Glassless, BC FIPS, and NSS providers.
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

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   @Param({"ECDH"})
   private String algorithm;

   private KeyPair aliceKeyPair;
   private KeyPair bobKeyPair;
   private KeyAgreement jdkKeyAgreement;
   private KeyAgreement glasslessKeyAgreement;
   private KeyAgreement bcFipsKeyAgreement;
   private KeyAgreement nssKeyAgreement;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      aliceKeyPair = kpg.generateKeyPair();
      bobKeyPair = kpg.generateKeyPair();

      jdkKeyAgreement = KeyAgreement.getInstance(algorithm);
      glasslessKeyAgreement = KeyAgreement.getInstance(algorithm, "Glassless");
      bcFipsKeyAgreement = KeyAgreement.getInstance(algorithm, "BCFIPS");

      // Try to configure NSS provider
      nssAvailable = false;
      try {
         Provider nssProvider = Security.getProvider("SunPKCS11");
         if (nssProvider != null) {
            Provider configuredNss = nssProvider.configure(NSS_CONFIG);
            Security.addProvider(configuredNss);
            nssKeyAgreement = KeyAgreement.getInstance(algorithm, configuredNss);
            nssAvailable = true;
         }
      } catch (Exception e) {
         System.err.println("NSS provider not available for KeyAgreement: " + e.getMessage());
      }
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

   @Benchmark
   public byte[] bcFipsKeyAgreement() throws Exception {
      bcFipsKeyAgreement.init(aliceKeyPair.getPrivate());
      bcFipsKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
      return bcFipsKeyAgreement.generateSecret();
   }

   @Benchmark
   public byte[] nssKeyAgreement() throws Exception {
      if (!nssAvailable) {
         return new byte[32];
      }
      nssKeyAgreement.init(aliceKeyPair.getPrivate());
      nssKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
      return nssKeyAgreement.generateSecret();
   }
}
