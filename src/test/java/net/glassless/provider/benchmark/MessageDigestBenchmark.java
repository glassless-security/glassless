package net.glassless.provider.benchmark;

import java.security.MessageDigest;
import java.security.Provider;
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
 * JMH benchmarks comparing MessageDigest performance between JDK, GlaSSLess, BC FIPS, and NSS providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=MessageDigestBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class MessageDigestBenchmark {

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   @Param({"SHA-256", "SHA-512"})
   private String algorithm;

   @Param({"64", "1024", "16384", "1048576"})
   private int dataSize;

   private byte[] data;
   private MessageDigest jdkDigest;
   private MessageDigest glasslessDigest;
   private MessageDigest bcFipsDigest;
   private MessageDigest nssDigest;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      // Try to configure NSS provider
      nssAvailable = false;
      try {
         Provider nssProvider = Security.getProvider("SunPKCS11");
         if (nssProvider != null) {
            Provider configuredNss = nssProvider.configure(NSS_CONFIG);
            Security.addProvider(configuredNss);
            nssDigest = MessageDigest.getInstance(algorithm, configuredNss);
            nssAvailable = true;
         }
      } catch (Exception e) {
         // NSS not available, skip those benchmarks
         System.err.println("NSS provider not available: " + e.getMessage());
      }

      data = new byte[dataSize];
      for (int i = 0; i < data.length; i++) {
         data[i] = (byte) i;
      }

      jdkDigest = MessageDigest.getInstance(algorithm);
      glasslessDigest = MessageDigest.getInstance(algorithm, "GlaSSLess");
      bcFipsDigest = MessageDigest.getInstance(algorithm, "BCFIPS");
   }

   @Benchmark
   public byte[] jdkDigest() {
      return jdkDigest.digest(data);
   }

   @Benchmark
   public byte[] glasslessDigest() {
      return glasslessDigest.digest(data);
   }

   @Benchmark
   public byte[] bcFipsDigest() {
      return bcFipsDigest.digest(data);
   }

   @Benchmark
   public byte[] nssDigest() {
      if (!nssAvailable) {
         return data; // Return input if NSS not available
      }
      return nssDigest.digest(data);
   }
}
