package net.glassless.provider.benchmark;

import java.security.MessageDigest;
import java.security.Security;
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
 * JMH benchmarks comparing MessageDigest performance between JDK and Glassless providers.
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

   @Param({"SHA-256", "SHA-512", "SHA3-256"})
   private String algorithm;

   @Param({"64", "1024", "16384", "1048576"})
   private int dataSize;

   private byte[] data;
   private MessageDigest jdkDigest;
   private MessageDigest glasslessDigest;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());

      data = new byte[dataSize];
      for (int i = 0; i < data.length; i++) {
         data[i] = (byte) i;
      }

      jdkDigest = MessageDigest.getInstance(algorithm);
      glasslessDigest = MessageDigest.getInstance(algorithm, "Glassless");
   }

   @Benchmark
   public byte[] jdkDigest() {
      return jdkDigest.digest(data);
   }

   @Benchmark
   public byte[] glasslessDigest() {
      return glasslessDigest.digest(data);
   }
}
