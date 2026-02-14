package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Tests for SLH-DSA (FIPS 205) Stateless Hash-Based Digital Signature Algorithm.
 * Tests will be skipped if OpenSSL 3.5+ is not available.
 */
public class SLHDSATest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    private static void assumeSLHDSAAvailable() {
        assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128f"),
            "SLH-DSA requires OpenSSL 3.5+");
    }

    @Nested
    @DisplayName("SLH-DSA-SHA2-128f Tests")
    class SLHDSA_SHA2_128fTests {

        @Test
        @DisplayName("Generate SLH-DSA-SHA2-128f key pair")
        void testGenerateKeyPair() throws Exception {
            assumeSLHDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());

            assertEquals("SLH-DSA-SHA2-128f", kp.getPublic().getAlgorithm());
            assertEquals("SLH-DSA-SHA2-128f", kp.getPrivate().getAlgorithm());
            assertEquals("X.509", kp.getPublic().getFormat());
            assertEquals("PKCS#8", kp.getPrivate().getFormat());
        }

        @Test
        @DisplayName("Sign and verify with SLH-DSA-SHA2-128f")
        void testSignAndVerify() throws Exception {
            assumeSLHDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test message".getBytes());
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(kp.getPublic());
            sig.update("test message".getBytes());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Verify fails with wrong message")
        void testVerifyFailsWithWrongMessage() throws Exception {
            assumeSLHDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("original message".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("different message".getBytes());
            assertFalse(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("SLH-DSA-SHA2-128s Tests")
    class SLHDSA_SHA2_128sTests {

        @Test
        @DisplayName("Generate SLH-DSA-SHA2-128s key pair")
        void testGenerateKeyPair() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128s"),
                "SLH-DSA-SHA2-128s requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128s", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("SLH-DSA-SHA2-128s", kp.getPublic().getAlgorithm());
        }

        @Test
        @DisplayName("Sign and verify with SLH-DSA-SHA2-128s")
        void testSignAndVerify() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128s"),
                "SLH-DSA-SHA2-128s requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128s", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SLH-DSA-SHA2-128s", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("SLH-DSA-SHAKE-128f Tests")
    class SLHDSA_SHAKE_128fTests {

        @Test
        @DisplayName("Generate SLH-DSA-SHAKE-128f key pair")
        void testGenerateKeyPair() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-128f"),
                "SLH-DSA-SHAKE-128f requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-128f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("SLH-DSA-SHAKE-128f", kp.getPublic().getAlgorithm());
        }

        @Test
        @DisplayName("Sign and verify with SLH-DSA-SHAKE-128f")
        void testSignAndVerify() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-128f"),
                "SLH-DSA-SHAKE-128f requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-128f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SLH-DSA-SHAKE-128f", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("SHAKE variant test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("SHAKE variant test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("SLH-DSA Higher Security Level Tests")
    class SLHDSAHigherSecurityTests {

        @Test
        @DisplayName("Generate and use SLH-DSA-SHA2-192f")
        void testSHA2_192f() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-192f"),
                "SLH-DSA-SHA2-192f requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-192f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SLH-DSA-SHA2-192f", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("192-bit security".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("192-bit security".getBytes());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Generate and use SLH-DSA-SHA2-256f")
        void testSHA2_256f() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-256f"),
                "SLH-DSA-SHA2-256f requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-256f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SLH-DSA-SHA2-256f", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("256-bit security".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("256-bit security".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("SLH-DSA KeyFactory Tests")
    class SLHDSAKeyFactoryTests {

        @Test
        @DisplayName("Reconstruct SLH-DSA keys from encoded")
        void testReconstructKeys() throws Exception {
            assumeSLHDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            KeyPair original = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "GlaSSLess");

            // Reconstruct public key
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(original.getPublic().getEncoded());
            PublicKey reconstructedPub = kf.generatePublic(pubSpec);
            assertArrayEquals(original.getPublic().getEncoded(), reconstructedPub.getEncoded());

            // Reconstruct private key
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(original.getPrivate().getEncoded());
            PrivateKey reconstructedPriv = kf.generatePrivate(privSpec);
            assertArrayEquals(original.getPrivate().getEncoded(), reconstructedPriv.getEncoded());

            // Use reconstructed keys for signing
            Signature sig = Signature.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            sig.initSign(reconstructedPriv);
            sig.update("test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(reconstructedPub);
            sig.update("test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("SLH-DSA Generic Tests")
    class SLHDSAGenericTests {

        @Test
        @DisplayName("Generic SLH-DSA with NamedParameterSpec")
        void testGenericSLHDSAWithSpec() throws Exception {
            assumeSLHDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "GlaSSLess");
            kpg.initialize(new NamedParameterSpec("SLH-DSA-SHA2-128f"));
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("SLH-DSA-SHA2-128f", kp.getPublic().getAlgorithm());
        }

        @Test
        @DisplayName("Generic SLH-DSA signature")
        void testGenericSLHDSASignature() throws Exception {
            assumeSLHDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128f", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            // Use generic SLH-DSA signature
            Signature sig = Signature.getInstance("SLH-DSA", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("generic test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("generic test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }
}
