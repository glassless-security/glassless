package net.glassless.provider.benchmark;

import java.security.SecureRandom;
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
 * JMH benchmarks comparing SecureRandom performance between JDK and Glassless providers.
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

   @Param({"16", "32", "64", "256", "1024", "4096"})
   private int byteCount;

   private byte[] buffer;
   private SecureRandom jdkRandom;
   private SecureRandom glasslessRandom;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());

      buffer = new byte[byteCount];
      jdkRandom = SecureRandom.getInstance("NativePRNG");
      glasslessRandom = SecureRandom.getInstance("NativePRNG", "Glassless");
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
}
