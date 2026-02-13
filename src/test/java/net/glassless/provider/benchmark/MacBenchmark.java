package net.glassless.provider.benchmark;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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
 * JMH benchmarks comparing MAC performance between JDK, Glassless, BC FIPS, and NSS providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=MacBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class MacBenchmark {

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   // HmacSHA256/512 available in NSS, SHA3 variants may not be
   @Param({"HmacSHA256", "HmacSHA512"})
   private String algorithm;

   @Param({"64", "1024", "16384", "1048576"})
   private int dataSize;

   private byte[] data;
   private Mac jdkMac;
   private Mac glasslessMac;
   private Mac bcFipsMac;
   private Mac nssMac;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      data = new byte[dataSize];
      for (int i = 0; i < data.length; i++) {
         data[i] = (byte) i;
      }

      byte[] keyBytes = new byte[32];
      new SecureRandom().nextBytes(keyBytes);
      SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);

      jdkMac = Mac.getInstance(algorithm);
      jdkMac.init(keySpec);

      glasslessMac = Mac.getInstance(algorithm, "Glassless");
      glasslessMac.init(keySpec);

      bcFipsMac = Mac.getInstance(algorithm, "BCFIPS");
      bcFipsMac.init(keySpec);

      // Try to configure NSS provider
      nssAvailable = false;
      try {
         Provider nssProvider = Security.getProvider("SunPKCS11");
         if (nssProvider != null) {
            Provider configuredNss = nssProvider.configure(NSS_CONFIG);
            Security.addProvider(configuredNss);
            nssMac = Mac.getInstance(algorithm, configuredNss);
            nssMac.init(keySpec);
            nssAvailable = true;
         }
      } catch (Exception e) {
         System.err.println("NSS provider not available for MAC: " + e.getMessage());
      }
   }

   @Benchmark
   public byte[] jdkMac() {
      return jdkMac.doFinal(data);
   }

   @Benchmark
   public byte[] glasslessMac() {
      return glasslessMac.doFinal(data);
   }

   @Benchmark
   public byte[] bcFipsMac() {
      return bcFipsMac.doFinal(data);
   }

   @Benchmark
   public byte[] nssMac() {
      if (!nssAvailable) {
         return data;
      }
      return nssMac.doFinal(data);
   }
}
