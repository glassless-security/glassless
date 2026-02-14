package net.glassless.provider.benchmark;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
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
 * JMH benchmarks comparing SecureRandom performance between JDK, GlaSSLess, BC FIPS, and NSS providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=SecureRandomBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class SecureRandomBenchmark {

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   @Param({"16", "32", "64", "256", "1024", "4096"})
   private int byteCount;

   private byte[] buffer;
   private SecureRandom jdkRandom;
   private SecureRandom glasslessRandom;
   private SecureRandom bcFipsRandom;
   private SecureRandom nssRandom;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      buffer = new byte[byteCount];
      jdkRandom = SecureRandom.getInstance("NativePRNG");
      glasslessRandom = SecureRandom.getInstance("NativePRNG", "GlaSSLess");
      // BC FIPS uses DEFAULT as its standard DRBG
      bcFipsRandom = SecureRandom.getInstance("DEFAULT", "BCFIPS");

      // Try to configure NSS provider
      nssAvailable = false;
      try {
         Provider nssProvider = Security.getProvider("SunPKCS11");
         if (nssProvider != null) {
            Provider configuredNss = nssProvider.configure(NSS_CONFIG);
            Security.addProvider(configuredNss);
            // NSS provides PKCS11 SecureRandom
            nssRandom = SecureRandom.getInstance("PKCS11", configuredNss);
            nssAvailable = true;
         }
      } catch (Exception e) {
         System.err.println("NSS provider not available for SecureRandom: " + e.getMessage());
      }
   }

   @Benchmark
   public byte[] jdkNextBytes() {
      jdkRandom.nextBytes(buffer);
      return buffer;
   }

   @Benchmark
   public byte[] glasslessNextBytes() {
      glasslessRandom.nextBytes(buffer);
      return buffer;
   }

   @Benchmark
   public byte[] bcFipsNextBytes() {
      bcFipsRandom.nextBytes(buffer);
      return buffer;
   }

   @Benchmark
   public byte[] nssNextBytes() {
      if (!nssAvailable) {
         jdkRandom.nextBytes(buffer);
         return buffer;
      }
      nssRandom.nextBytes(buffer);
      return buffer;
   }
}
