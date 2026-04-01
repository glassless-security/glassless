package net.glassless.provider;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import net.glassless.provider.internal.OpenSSLCrypto;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Tests for Deterministic ECDSA (RFC 6979 / FIPS 186-5).
 * Deterministic ECDSA produces identical signatures for the same message and key,
 * unlike standard ECDSA which uses random nonces.
 */
public class DeterministicECDSATest {

   @BeforeAll
   public static void setUp() {
      Security.addProvider(new GlaSSLessProvider());
      Assumptions.assumeTrue(OpenSSLCrypto.isVersionAtLeast(3, 2, 0),
         "Deterministic ECDSA (RFC 6979) requires OpenSSL 3.2+");
   }

   private KeyPair generateKeyPair(String curve) throws Exception {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
      kpg.initialize(new ECGenParameterSpec(curve));
      return kpg.generateKeyPair();
   }

   @ParameterizedTest(name = "{0} with {1}")
   @DisplayName("Deterministic ECDSA sign and verify")
   @CsvSource({
      "SHA224withDetECDSA, secp256r1",
      "SHA256withDetECDSA, secp256r1",
      "SHA384withDetECDSA, secp384r1",
      "SHA512withDetECDSA, secp521r1",
      "SHA3-256withDetECDSA, secp256r1",
      "SHA3-384withDetECDSA, secp384r1",
      "SHA3-512withDetECDSA, secp521r1"
   })
   void testSignAndVerify(String algorithm, String curve) throws Exception {
      KeyPair keyPair = generateKeyPair(curve);
      byte[] message = "Deterministic ECDSA test message".getBytes();

      Signature signer = Signature.getInstance(algorithm, PROVIDER_NAME);
      signer.initSign(keyPair.getPrivate());
      signer.update(message);
      byte[] signature = signer.sign();
      assertNotNull(signature);

      Signature verifier = Signature.getInstance(algorithm, PROVIDER_NAME);
      verifier.initVerify(keyPair.getPublic());
      verifier.update(message);
      assertTrue(verifier.verify(signature), "Signature should verify");
   }

   @ParameterizedTest(name = "{0}")
   @DisplayName("Deterministic ECDSA produces identical signatures for same input")
   @CsvSource({
      "SHA256withDetECDSA",
      "SHA384withDetECDSA",
      "SHA512withDetECDSA"
   })
   void testDeterminism(String algorithm) throws Exception {
      KeyPair keyPair = generateKeyPair("secp256r1");
      byte[] message = "Same message, same key, same signature".getBytes();

      Signature sig1 = Signature.getInstance(algorithm, PROVIDER_NAME);
      sig1.initSign(keyPair.getPrivate());
      sig1.update(message);
      byte[] signature1 = sig1.sign();

      Signature sig2 = Signature.getInstance(algorithm, PROVIDER_NAME);
      sig2.initSign(keyPair.getPrivate());
      sig2.update(message);
      byte[] signature2 = sig2.sign();

      assertArrayEquals(signature1, signature2,
         "Deterministic ECDSA should produce identical signatures for the same message and key");
   }

   @Test
   @DisplayName("Standard ECDSA produces different signatures (non-deterministic)")
   void testStandardECDSAIsNonDeterministic() throws Exception {
      KeyPair keyPair = generateKeyPair("secp256r1");
      byte[] message = "Non-deterministic test".getBytes();

      Signature sig1 = Signature.getInstance("SHA256withECDSA", PROVIDER_NAME);
      sig1.initSign(keyPair.getPrivate());
      sig1.update(message);
      byte[] signature1 = sig1.sign();

      Signature sig2 = Signature.getInstance("SHA256withECDSA", PROVIDER_NAME);
      sig2.initSign(keyPair.getPrivate());
      sig2.update(message);
      byte[] signature2 = sig2.sign();

      assertFalse(Arrays.equals(signature1, signature2),
         "Standard ECDSA should produce different signatures due to random nonces");
   }

   @Test
   @DisplayName("Deterministic ECDSA detects modified message")
   void testModifiedMessage() throws Exception {
      KeyPair keyPair = generateKeyPair("secp256r1");
      byte[] message = "Original message".getBytes();

      Signature signer = Signature.getInstance("SHA256withDetECDSA", PROVIDER_NAME);
      signer.initSign(keyPair.getPrivate());
      signer.update(message);
      byte[] signature = signer.sign();

      byte[] modifiedMessage = "Modified message".getBytes();
      Signature verifier = Signature.getInstance("SHA256withDetECDSA", PROVIDER_NAME);
      verifier.initVerify(keyPair.getPublic());
      verifier.update(modifiedMessage);
      assertFalse(verifier.verify(signature), "Modified message should fail verification");
   }

   @Test
   @DisplayName("Deterministic ECDSA signature verifiable with standard ECDSA verifier")
   void testCrossVerification() throws Exception {
      KeyPair keyPair = generateKeyPair("secp256r1");
      byte[] message = "Cross verification test".getBytes();

      // Sign with deterministic ECDSA
      Signature signer = Signature.getInstance("SHA256withDetECDSA", PROVIDER_NAME);
      signer.initSign(keyPair.getPrivate());
      signer.update(message);
      byte[] signature = signer.sign();

      // Verify with standard ECDSA (should work since output format is identical)
      Signature verifier = Signature.getInstance("SHA256withECDSA", PROVIDER_NAME);
      verifier.initVerify(keyPair.getPublic());
      verifier.update(message);
      assertTrue(verifier.verify(signature),
         "Deterministic ECDSA signature should be verifiable by standard ECDSA verifier");
   }
}
