package net.glassless.provider.benchmark;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

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
 * JMH benchmarks comparing Cipher performance between JDK, GlaSSLess, BC FIPS, and NSS providers.
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

   private static final String NSS_CONFIG = """
         name = NSS
         nssLibraryDirectory = /usr/lib/x86_64-linux-gnu
         nssDbMode = noDb
         attributes = compatibility
         """;

   // AES/CBC is available across all providers including NSS
   @Param({"AES/GCM/NoPadding", "AES/CBC/PKCS5Padding"})
   private String algorithm;

   @Param({"64", "1024", "16384", "1048576"})
   private int dataSize;

   private byte[] plaintext;
   private byte[] ciphertext;
   private byte[] bcCiphertext;
   private byte[] nssCiphertext;
   private Cipher jdkEncrypt;
   private Cipher jdkDecrypt;
   private Cipher glasslessEncrypt;
   private Cipher glasslessDecrypt;
   private Cipher bcFipsEncrypt;
   private Cipher bcFipsDecrypt;
   private Cipher nssEncrypt;
   private Cipher nssDecrypt;
   private boolean nssAvailable;

   @Setup(Level.Trial)
   public void setup() throws Exception {
      Security.addProvider(new GlaSSLessProvider());
      Security.addProvider(new BouncyCastleFipsProvider());

      plaintext = new byte[dataSize];
      SecureRandom random = new SecureRandom();
      random.nextBytes(plaintext);

      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);
      SecretKey key = keyGen.generateKey();

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

      if (algorithm.contains("GCM")) {
         byte[] iv = new byte[12];
         random.nextBytes(iv);
         GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

         jdkEncrypt = Cipher.getInstance(algorithm);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

         jdkDecrypt = Cipher.getInstance(algorithm);
         jdkDecrypt.init(Cipher.DECRYPT_MODE, key, gcmSpec);

         glasslessEncrypt = Cipher.getInstance(algorithm, "GlaSSLess");
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

         glasslessDecrypt = Cipher.getInstance(algorithm, "GlaSSLess");
         glasslessDecrypt.init(Cipher.DECRYPT_MODE, key, gcmSpec);

         bcFipsEncrypt = Cipher.getInstance(algorithm, "BCFIPS");
         bcFipsEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

         bcFipsDecrypt = Cipher.getInstance(algorithm, "BCFIPS");
         bcFipsDecrypt.init(Cipher.DECRYPT_MODE, key, gcmSpec);

         ciphertext = jdkEncrypt.doFinal(plaintext);
         bcCiphertext = bcFipsEncrypt.doFinal(plaintext);

         if (nssAvailable) {
            try {
               nssEncrypt = Cipher.getInstance(algorithm, configuredNss);
               nssEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
               nssDecrypt = Cipher.getInstance(algorithm, configuredNss);
               nssDecrypt.init(Cipher.DECRYPT_MODE, key, gcmSpec);
               nssCiphertext = nssEncrypt.doFinal(plaintext);
               nssEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            } catch (Exception e) {
               nssAvailable = false;
            }
         }

         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
         bcFipsEncrypt.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
      } else {
         byte[] iv = new byte[16];
         random.nextBytes(iv);
         IvParameterSpec ivSpec = new IvParameterSpec(iv);

         jdkEncrypt = Cipher.getInstance(algorithm);
         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         jdkDecrypt = Cipher.getInstance(algorithm);
         jdkDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         glasslessEncrypt = Cipher.getInstance(algorithm, "GlaSSLess");
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         glasslessDecrypt = Cipher.getInstance(algorithm, "GlaSSLess");
         glasslessDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         bcFipsEncrypt = Cipher.getInstance(algorithm, "BCFIPS");
         bcFipsEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

         bcFipsDecrypt = Cipher.getInstance(algorithm, "BCFIPS");
         bcFipsDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

         ciphertext = jdkEncrypt.doFinal(plaintext);
         bcCiphertext = bcFipsEncrypt.doFinal(plaintext);

         if (nssAvailable) {
            try {
               nssEncrypt = Cipher.getInstance(algorithm, configuredNss);
               nssEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
               nssDecrypt = Cipher.getInstance(algorithm, configuredNss);
               nssDecrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
               nssCiphertext = nssEncrypt.doFinal(plaintext);
               nssEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            } catch (Exception e) {
               nssAvailable = false;
            }
         }

         jdkEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
         glasslessEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
         bcFipsEncrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
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
   public byte[] bcFipsEncrypt() throws Exception {
      return bcFipsEncrypt.doFinal(plaintext);
   }

   @Benchmark
   public byte[] nssEncrypt() throws Exception {
      if (!nssAvailable) {
         return plaintext;
      }
      return nssEncrypt.doFinal(plaintext);
   }

   @Benchmark
   public byte[] jdkDecrypt() throws Exception {
      return jdkDecrypt.doFinal(ciphertext);
   }

   @Benchmark
   public byte[] glasslessDecrypt() throws Exception {
      return glasslessDecrypt.doFinal(ciphertext);
   }

   @Benchmark
   public byte[] bcFipsDecrypt() throws Exception {
      return bcFipsDecrypt.doFinal(bcCiphertext);
   }

   @Benchmark
   public byte[] nssDecrypt() throws Exception {
      if (!nssAvailable) {
         return plaintext;
      }
      return nssDecrypt.doFinal(nssCiphertext);
   }
}
