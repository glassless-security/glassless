package net.glassless.provider.benchmark;

import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

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
 * JMH benchmarks comparing Cipher performance between JDK and Glassless providers.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=CipherBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class CipherBenchmark {

   @Param({"AES/GCM/NoPadding", "AES/CBC/PKCS5Padding", "ChaCha20-Poly1305"})
   private String algorithm;

   @Param({"64", "1024", "16384", "1048576"})
   private int dataSize;

   private byte[] plaintext;
   private byte[] ciphertext;
   private Cipher jdkEncrypt;
   private Cipher jdkDecrypt;
   private Cipher glasslessEncrypt;
   private Cipher glasslessDecrypt;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlasslessProvider());

      plaintext = new byte[dataSize];
      SecureRandom random = new SecureRandom();
      random.nextBytes(plaintext);

      String keyAlg = algorithm.startsWith("ChaCha") ? "ChaCha20" : "AES";
      int keySize = algorithm.startsWith("ChaCha") ? 256 : 256;

      KeyGenerator keyGen = KeyGenerator.getInstance(keyAlg);
      keyGen.init(keySize);
      SecretKey key = keyGen.generateKey();

      if (algorithm.contains("GCM")) {
         byte[] iv = new byte[12];
         random.nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         jdkEncrypt = Cipher.getInstance(algorithm);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

         jdkDecrypt = Cipher.getInstance(algorithm);
         jdkDecrypt.init(Cipher.DECRYPT_MODE, key, gcmSpec);

         glasslessEncrypt = Cipher.getInstance(algorithm, "Glassless");
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

         glasslessDecrypt = Cipher.getInstance(algorithm, "Glassless");
         glasslessDecrypt.init(Cipher.DECRYPT_MODE, key, gcmSpec);

         ciphertext = jdkEncrypt.doFinal(plaintext);
         // Re-init after encryption
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
      } else if (algorithm.contains("ChaCha")) {
         byte[] nonce = new byte[12];
         random.nextBytes(nonce);
         IvParameterSpec ivSpec = new IvParameterSpec(nonce);

         jdkEncrypt = Cipher.getInstance(algorithm);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         jdkDecrypt = Cipher.getInstance(algorithm);
         jdkDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         glasslessEncrypt = Cipher.getInstance(algorithm, "Glassless");
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         glasslessDecrypt = Cipher.getInstance(algorithm, "Glassless");
         glasslessDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         ciphertext = jdkEncrypt.doFinal(plaintext);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      } else {
         byte[] iv = new byte[16];
         random.nextBytes(iv);
         IvParameterSpec ivSpec = new IvParameterSpec(iv);

         jdkEncrypt = Cipher.getInstance(algorithm);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         jdkDecrypt = Cipher.getInstance(algorithm);
         jdkDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         glasslessEncrypt = Cipher.getInstance(algorithm, "Glassless");
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         glasslessDecrypt = Cipher.getInstance(algorithm, "Glassless");
         glasslessDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         ciphertext = jdkEncrypt.doFinal(plaintext);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      }
   }

   @Benchmark
   public byte[] jdkEncrypt() throws Exception {
      return jdkEncrypt.doFinal(plaintext);
   }

   @Benchmark
   public byte[] glasslessEncrypt() throws Exception {
      return glasslessEncrypt.doFinal(plaintext);
   }

   @Benchmark
   public byte[] jdkDecrypt() throws Exception {
      return jdkDecrypt.doFinal(ciphertext);
   }

   @Benchmark
   public byte[] glasslessDecrypt() throws Exception {
      return glasslessDecrypt.doFinal(ciphertext);
   }
}
