package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class EdDSATest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("Ed25519 KeyPairGenerator Tests")
    class Ed25519KeyPairGeneratorTests {

        @Test
        @DisplayName("Generate Ed25519 key pair")
        void testGenerateKeyPair() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());

            assertTrue(kp.getPublic() instanceof EdECPublicKey);
            assertTrue(kp.getPrivate() instanceof EdECPrivateKey);

            EdECPublicKey pub = (EdECPublicKey) kp.getPublic();
            EdECPrivateKey priv = (EdECPrivateKey) kp.getPrivate();

            assertEquals("EdDSA", pub.getAlgorithm());
            assertEquals("EdDSA", priv.getAlgorithm());
            assertEquals("X.509", pub.getFormat());
            assertEquals("PKCS#8", priv.getFormat());

            // Ed25519 key sizes
            assertEquals(44, pub.getEncoded().length);
            assertEquals(48, priv.getEncoded().length);
            assertTrue(priv.getBytes().isPresent());
            assertEquals(32, priv.getBytes().get().length);
        }

        @Test
        @DisplayName("Generate EdDSA key pair with Ed25519 param")
        void testGenerateKeyPairWithParam() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", "GlaSSLess");
            kpg.initialize(NamedParameterSpec.ED25519);
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            EdECPublicKey pub = (EdECPublicKey) kp.getPublic();
            assertEquals(44, pub.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("Ed448 KeyPairGenerator Tests")
    class Ed448KeyPairGeneratorTests {

        @Test
        @DisplayName("Generate Ed448 key pair")
        void testGenerateKeyPair() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertTrue(kp.getPublic() instanceof EdECPublicKey);
            assertTrue(kp.getPrivate() instanceof EdECPrivateKey);

            EdECPublicKey pub = (EdECPublicKey) kp.getPublic();
            EdECPrivateKey priv = (EdECPrivateKey) kp.getPrivate();

            // Ed448 key sizes
            assertEquals(69, pub.getEncoded().length);
            assertEquals(73, priv.getEncoded().length);
            assertTrue(priv.getBytes().isPresent());
            assertEquals(57, priv.getBytes().get().length);
        }
    }

    @Nested
    @DisplayName("Ed25519 Signature Tests")
    class Ed25519SignatureTests {

        @Test
        @DisplayName("Sign and verify with Ed25519")
        void testSignAndVerify() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("Ed25519", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test message".getBytes());
            byte[] signature = sig.sign();

            assertNotNull(signature);
            assertEquals(64, signature.length);  // Ed25519 signature is 64 bytes

            sig.initVerify(kp.getPublic());
            sig.update("test message".getBytes());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Verify fails with wrong message")
        void testVerifyFailsWithWrongMessage() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("Ed25519", "GlaSSLess");
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
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("Ed25519", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("EdDSA signature with Ed25519 key")
        void testEdDSASignatureWithEd25519() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("EdDSA", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(kp.getPublic());
            sig.update("test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("Ed448 Signature Tests")
    class Ed448SignatureTests {

        @Test
        @DisplayName("Sign and verify with Ed448")
        void testSignAndVerify() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("Ed448", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("test message".getBytes());
            byte[] signature = sig.sign();

            assertNotNull(signature);
            assertEquals(114, signature.length);  // Ed448 signature is 114 bytes

            sig.initVerify(kp.getPublic());
            sig.update("test message".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("EdDSA KeyFactory Tests")
    class EdDSAKeyFactoryTests {

        @Test
        @DisplayName("Reconstruct Ed25519 keys from encoded")
        void testReconstructEd25519Keys() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair original = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("EdDSA", "GlaSSLess");

            // Reconstruct public key
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(original.getPublic().getEncoded());
            EdECPublicKey reconstructedPub = (EdECPublicKey) kf.generatePublic(pubSpec);
            assertArrayEquals(original.getPublic().getEncoded(), reconstructedPub.getEncoded());

            // Reconstruct private key
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(original.getPrivate().getEncoded());
            EdECPrivateKey reconstructedPriv = (EdECPrivateKey) kf.generatePrivate(privSpec);
            assertArrayEquals(original.getPrivate().getEncoded(), reconstructedPriv.getEncoded());
        }

        @Test
        @DisplayName("Get key specs from keys")
        void testGetKeySpecs() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("EdDSA", "GlaSSLess");

            // Get X509 spec from public key
            X509EncodedKeySpec x509Spec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
            assertNotNull(x509Spec);
            assertArrayEquals(kp.getPublic().getEncoded(), x509Spec.getEncoded());

            // Get PKCS8 spec from private key
            PKCS8EncodedKeySpec pkcs8Spec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
            assertNotNull(pkcs8Spec);
            assertArrayEquals(kp.getPrivate().getEncoded(), pkcs8Spec.getEncoded());

            // Get EdEC specs
            EdECPublicKeySpec edPubSpec = kf.getKeySpec(kp.getPublic(), EdECPublicKeySpec.class);
            assertNotNull(edPubSpec);
            assertNotNull(edPubSpec.getPoint());

            EdECPrivateKeySpec edPrivSpec = kf.getKeySpec(kp.getPrivate(), EdECPrivateKeySpec.class);
            assertNotNull(edPrivSpec);
            assertEquals(32, edPrivSpec.getBytes().length);
        }

        @Test
        @DisplayName("Translate keys from other provider")
        void testTranslateKeys() throws Exception {
            // Generate with default provider
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair original = kpg.generateKeyPair();

            // Translate to GlaSSLess
            KeyFactory kf = KeyFactory.getInstance("EdDSA", "GlaSSLess");
            EdECPublicKey translatedPub = (EdECPublicKey) kf.translateKey(original.getPublic());
            EdECPrivateKey translatedPriv = (EdECPrivateKey) kf.translateKey(original.getPrivate());

            assertNotNull(translatedPub);
            assertNotNull(translatedPriv);

            // Use translated keys for signing
            Signature sig = Signature.getInstance("Ed25519", "GlaSSLess");
            sig.initSign(translatedPriv);
            sig.update("test".getBytes());
            byte[] signature = sig.sign();

            sig.initVerify(translatedPub);
            sig.update("test".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("Cross-provider Compatibility Tests")
    class CrossProviderTests {

        @Test
        @DisplayName("GlaSSLess signs, SunEC verifies")
        void testGlaSSLessSignSunVerify() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            // Sign with GlaSSLess
            Signature sig = Signature.getInstance("Ed25519", "GlaSSLess");
            sig.initSign(kp.getPrivate());
            sig.update("cross-provider test".getBytes());
            byte[] signature = sig.sign();

            // Verify with default provider (SunEC)
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            EdECPublicKey sunPub = (EdECPublicKey) kf.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));

            Signature sunSig = Signature.getInstance("Ed25519");
            sunSig.initVerify(sunPub);
            sunSig.update("cross-provider test".getBytes());
            assertTrue(sunSig.verify(signature));
        }

        @Test
        @DisplayName("SunEC signs, GlaSSLess verifies")
        void testSunSignGlaSSLessVerify() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();

            // Sign with default provider
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(kp.getPrivate());
            sig.update("reverse cross-provider test".getBytes());
            byte[] signature = sig.sign();

            // Verify with GlaSSLess
            KeyFactory kf = KeyFactory.getInstance("EdDSA", "GlaSSLess");
            EdECPublicKey glassPub = (EdECPublicKey) kf.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));

            Signature glassSig = Signature.getInstance("Ed25519", "GlaSSLess");
            glassSig.initVerify(glassPub);
            glassSig.update("reverse cross-provider test".getBytes());
            assertTrue(glassSig.verify(signature));
        }
    }
}
