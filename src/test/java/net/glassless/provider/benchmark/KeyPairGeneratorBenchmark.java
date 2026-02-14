package net.glassless.provider.benchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
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

import net.glassless.provider.GlaSSLessProvider;

/**
 * JMH benchmarks comparing KeyPairGenerator performance between JDK, GlaSSLess, BC FIPS, and NSS providers.
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

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   // Note: Ed25519/X25519 not available in BC FIPS 2.x
   @Param({"EC-P256", "EC-P384", "RSA-2048", "RSA-4096"})
   private String algorithm;

   private KeyPairGenerator jdkKeyPairGen;
   private KeyPairGenerator glasslessKeyPairGen;
   private KeyPairGenerator bcFipsKeyPairGen;
   private KeyPairGenerator nssKeyPairGen;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      // Try to configure NSS provider
      nssAvailable = false;
      Provider configuredNss = null;
      try {
         Provider nssProvider = Security.getProvider("SunPKCS11");
         if (nssProvider != null) {
            configuredNss = nssProvider.configure(NSS_CONFIG);
            Security.addProvider(configuredNss);
            nssAvailable = true;
         }
      } catch (Exception e) {
         System.err.println("NSS provider not available: " + e.getMessage());
      }

      if (algorithm.startsWith("EC-")) {
         String curve = algorithm.equals("EC-P256") ? "secp256r1" : "secp384r1";

         jdkKeyPairGen = KeyPairGenerator.getInstance("EC");
         jdkKeyPairGen.initialize(new ECGenParameterSpec(curve));

         glasslessKeyPairGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
         glasslessKeyPairGen.initialize(new ECGenParameterSpec(curve));

         bcFipsKeyPairGen = KeyPairGenerator.getInstance("EC", "BCFIPS");
         bcFipsKeyPairGen.initialize(new ECGenParameterSpec(curve));

         if (nssAvailable) {
            try {
               nssKeyPairGen = KeyPairGenerator.getInstance("EC", configuredNss);
               nssKeyPairGen.initialize(new ECGenParameterSpec(curve));
            } catch (Exception e) {
               nssAvailable = false;
            }
         }
      } else if (algorithm.startsWith("RSA-")) {
         int keySize = Integer.parseInt(algorithm.split("-")[1]);

         jdkKeyPairGen = KeyPairGenerator.getInstance("RSA");
         jdkKeyPairGen.initialize(keySize);

         glasslessKeyPairGen = KeyPairGenerator.getInstance("RSA", "GlaSSLess");
         glasslessKeyPairGen.initialize(keySize);

         bcFipsKeyPairGen = KeyPairGenerator.getInstance("RSA", "BCFIPS");
         bcFipsKeyPairGen.initialize(keySize);

         if (nssAvailable) {
            try {
               nssKeyPairGen = KeyPairGenerator.getInstance("RSA", configuredNss);
               nssKeyPairGen.initialize(keySize);
            } catch (Exception e) {
               nssAvailable = false;
            }
         }
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

   @Benchmark
   public KeyPair bcFipsGenerateKeyPair() {
      return bcFipsKeyPairGen.generateKeyPair();
   }

   @Benchmark
   public KeyPair nssGenerateKeyPair() {
      if (!nssAvailable) {
         return jdkKeyPairGen.generateKeyPair();
      }
      return nssKeyPairGen.generateKeyPair();
   }
}
