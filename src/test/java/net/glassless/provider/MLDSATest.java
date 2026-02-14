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
 * Tests for ML-DSA (FIPS 204) Module-Lattice Digital Signature Algorithm.
 * Tests will be skipped if OpenSSL 3.5+ is not available.
 */
public class MLDSATest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    private static void assumeMLDSAAvailable() {
        assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa65"),
            "ML-DSA requires OpenSSL 3.5+");
    }

    @Nested
    @DisplayName("ML-DSA-44 Tests")
    class MLDSA44Tests {

        @Test
        @DisplayName("Generate ML-DSA-44 key pair")
        void testGenerateKeyPair() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa44"),
                "ML-DSA-44 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());

            assertEquals("ML-DSA-44", kp.getPublic().getAlgorithm());
            assertEquals("ML-DSA-44", kp.getPrivate().getAlgorithm());
            assertEquals("X.509", kp.getPublic().getFormat());
            assertEquals("PKCS#8", kp.getPrivate().getFormat());
        }

        @Test
        @DisplayName("Sign and verify with ML-DSA-44")
        void testSignAndVerify() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa44"),
                "ML-DSA-44 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("ML-DSA-44", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test message".getBytes());
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(kp.getPublic());
            sig.update("test message".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("ML-DSA-65 Tests")
    class MLDSA65Tests {

        @Test
        @DisplayName("Generate ML-DSA-65 key pair")
        void testGenerateKeyPair() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("ML-DSA-65", kp.getPublic().getAlgorithm());
            assertEquals("ML-DSA-65", kp.getPrivate().getAlgorithm());
        }

        @Test
        @DisplayName("Sign and verify with ML-DSA-65")
        void testSignAndVerify() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("ML-DSA-65", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("Hello, Post-Quantum World!".getBytes());
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(kp.getPublic());
            sig.update("Hello, Post-Quantum World!".getBytes());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Verify fails with wrong message")
        void testVerifyFailsWithWrongMessage() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("ML-DSA-65", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("original message".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("different message".getBytes());
            assertFalse(sig.verify(signature));
        }

        @Test
        @DisplayName("Sign empty message")
        void testSignEmptyMessage() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("ML-DSA-65", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Generic ML-DSA with NamedParameterSpec")
        void testGenericMLDSAWithSpec() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "GlaSSLess");
            kpg.initialize(new NamedParameterSpec("ML-DSA-65"));
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("ML-DSA-65", kp.getPublic().getAlgorithm());

            // Use generic signature
            Signature sig = Signature.getInstance("ML-DSA", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("ML-DSA-87 Tests")
    class MLDSA87Tests {

        @Test
        @DisplayName("Generate ML-DSA-87 key pair")
        void testGenerateKeyPair() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa87"),
                "ML-DSA-87 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("ML-DSA-87", kp.getPublic().getAlgorithm());
            assertEquals("ML-DSA-87", kp.getPrivate().getAlgorithm());
        }

        @Test
        @DisplayName("Sign and verify with ML-DSA-87")
        void testSignAndVerify() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa87"),
                "ML-DSA-87 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("ML-DSA-87", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test message".getBytes());
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(kp.getPublic());
            sig.update("test message".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("ML-DSA KeyFactory Tests")
    class MLDSAKeyFactoryTests {

        @Test
        @DisplayName("Reconstruct ML-DSA keys from encoded")
        void testReconstructKeys() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair original = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("ML-DSA", "GlaSSLess");

            // Reconstruct public key
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(original.getPublic().getEncoded());
            PublicKey reconstructedPub = kf.generatePublic(pubSpec);
            assertArrayEquals(original.getPublic().getEncoded(), reconstructedPub.getEncoded());

            // Reconstruct private key
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(original.getPrivate().getEncoded());
            PrivateKey reconstructedPriv = kf.generatePrivate(privSpec);
            assertArrayEquals(original.getPrivate().getEncoded(), reconstructedPriv.getEncoded());

            // Use reconstructed keys for signing
            Signature sig = Signature.getInstance("ML-DSA-65", "GlaSSLess");
            sig.initSign(reconstructedPriv);
            sig.update("test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(reconstructedPub);
            sig.update("test".getBytes());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Translate keys")
        void testTranslateKeys() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair original = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("ML-DSA", "GlaSSLess");

            PublicKey translatedPub = (PublicKey) kf.translateKey(original.getPublic());
            PrivateKey translatedPriv = (PrivateKey) kf.translateKey(original.getPrivate());

            assertNotNull(translatedPub);
            assertNotNull(translatedPriv);
            assertArrayEquals(original.getPublic().getEncoded(), translatedPub.getEncoded());
            assertArrayEquals(original.getPrivate().getEncoded(), translatedPriv.getEncoded());
        }
    }

    @Nested
    @DisplayName("ML-DSA Large Message Tests")
    class MLDSALargeMessageTests {

        @Test
        @DisplayName("Sign and verify large message")
        void testSignLargeMessage() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            // Create 1MB message
            byte[] largeMessage = new byte[1024 * 1024];
            for (int i = 0; i < largeMessage.length; i++) {
                largeMessage[i] = (byte) (i % 256);
            }

            Signature sig = Signature.getInstance("ML-DSA-65", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update(largeMessage);
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(kp.getPublic());
            sig.update(largeMessage);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Sign with multiple updates")
        void testSignWithMultipleUpdates() throws Exception {
            assumeMLDSAAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("ML-DSA-65", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("part1".getBytes());
            sig.update("part2".getBytes());
            sig.update("part3".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("part1".getBytes());
            sig.update("part2".getBytes());
            sig.update("part3".getBytes());
            assertTrue(sig.verify(signature));

            // Verify fails if parts are in different order
            sig.initVerify(kp.getPublic());
            sig.update("part3".getBytes());
            sig.update("part2".getBytes());
            sig.update("part1".getBytes());
            assertFalse(sig.verify(signature));
        }
    }
}
