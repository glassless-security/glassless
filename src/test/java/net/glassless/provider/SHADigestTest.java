package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.ValueSource;

@ParameterizedClass
@ValueSource(strings = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"})
public class SHADigestTest {

   @Parameter
   String algorithm;

   @BeforeAll
   static void setUp() {
      Security.addProvider(new GlaSSLessProvider());
   }

   @Test
   void testSHADigest() throws Exception {
      String testString = "Hello, FFM API with OpenSSL!";
      byte[] inputBytes = testString.getBytes(StandardCharsets.UTF_8);

      // Get MessageDigest instance from our OpenSSLProvider
      MessageDigest digest = MessageDigest.getInstance(algorithm, GlaSSLessProvider.PROVIDER_NAME);
      assertNotNull(digest, "MessageDigest should not be null");
      assertEquals(GlaSSLessProvider.PROVIDER_NAME, digest.getProvider().getName(), "Provider name mismatch");

      // Perform digest
      digest.update(inputBytes);
      byte[] openSSLHash = digest.digest();

      // Get MessageDigest instance from default Java provider for comparison
      MessageDigest javaDigest = MessageDigest.getInstance(algorithm);
      javaDigest.update(inputBytes);
      byte[] javaHash = javaDigest.digest();

      // Compare hashes
      assertArrayEquals(javaHash, openSSLHash, "Hashes from OpenSSLProvider and Java's default provider should match");
   }

   @Test
   void testSHADigestWithMultipleUpdates() throws Exception {
      String testStringPart1 = "Hello, ";
      String testStringPart2 = "FFM API ";
      String testStringPart3 = "with OpenSSL!";
      byte[] inputBytesPart1 = testStringPart1.getBytes(StandardCharsets.UTF_8);
      byte[] inputBytesPart2 = testStringPart2.getBytes(StandardCharsets.UTF_8);
      byte[] inputBytesPart3 = testStringPart3.getBytes(StandardCharsets.UTF_8);

      // OpenSSL Provider
      MessageDigest digest = MessageDigest.getInstance(algorithm, GlaSSLessProvider.PROVIDER_NAME);
      digest.update(inputBytesPart1);
      digest.update(inputBytesPart2);
      digest.update(inputBytesPart3);
      byte[] openSSLHash = digest.digest();

      // Java Default Provider
      MessageDigest javaDigest = MessageDigest.getInstance(algorithm);
      javaDigest.update(inputBytesPart1);
      javaDigest.update(inputBytesPart2);
      javaDigest.update(inputBytesPart3);
      byte[] javaHash = javaDigest.digest();

      assertArrayEquals(javaHash, openSSLHash, "Hashes from multiple updates should match");
   }

   @Test
   void testDigestReset() throws Exception {
      String testString1 = "First string";
      String testString2 = "Second string";
      byte[] inputBytes1 = testString1.getBytes(StandardCharsets.UTF_8);
      byte[] inputBytes2 = testString2.getBytes(StandardCharsets.UTF_8);

      MessageDigest digest = MessageDigest.getInstance(algorithm, GlaSSLessProvider.PROVIDER_NAME);

      // First digest
      digest.update(inputBytes1);
      byte[] hash1 = digest.digest();

      // Reset and second digest
      digest.update(inputBytes2);
      byte[] hash2 = digest.digest();

      MessageDigest javaDigest1 = MessageDigest.getInstance(algorithm);
      javaDigest1.update(inputBytes1);
      byte[] expectedHash1 = javaDigest1.digest();

      MessageDigest javaDigest2 = MessageDigest.getInstance(algorithm);
      javaDigest2.update(inputBytes2);
      byte[] expectedHash2 = javaDigest2.digest();

      assertArrayEquals(expectedHash1, hash1, "First hash after reset should match");
      assertArrayEquals(expectedHash2, hash2, "Second hash after reset should match");
   }
}
