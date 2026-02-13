package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class XDHTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlasslessProvider());
    }

    @Nested
    @DisplayName("X25519 KeyPairGenerator Tests")
    class X25519KeyPairGeneratorTests {

        @Test
        @DisplayName("Generate X25519 key pair")
        void testGenerateKeyPair() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());

            assertTrue(kp.getPublic() instanceof XECPublicKey);
            assertTrue(kp.getPrivate() instanceof XECPrivateKey);

            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            XECPrivateKey priv = (XECPrivateKey) kp.getPrivate();

            assertEquals("XDH", pub.getAlgorithm());
            assertEquals("XDH", priv.getAlgorithm());
            assertEquals("X.509", pub.getFormat());
            assertEquals("PKCS#8", priv.getFormat());

            // X25519 key sizes
            assertEquals(44, pub.getEncoded().length);
            assertEquals(48, priv.getEncoded().length);
            assertTrue(priv.getScalar().isPresent());
            assertEquals(32, priv.getScalar().get().length);

            // Check u-coordinate
            assertNotNull(pub.getU());
        }

        @Test
        @DisplayName("Generate XDH key pair with X25519 param")
        void testGenerateKeyPairWithParam() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH", "Glassless");
            kpg.initialize(NamedParameterSpec.X25519);
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            assertEquals(44, pub.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("X448 KeyPairGenerator Tests")
    class X448KeyPairGeneratorTests {

        @Test
        @DisplayName("Generate X448 key pair")
        void testGenerateKeyPair() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X448", "Glassless");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertTrue(kp.getPublic() instanceof XECPublicKey);
            assertTrue(kp.getPrivate() instanceof XECPrivateKey);

            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            XECPrivateKey priv = (XECPrivateKey) kp.getPrivate();

            // X448 key sizes
            assertEquals(68, pub.getEncoded().length);
            assertEquals(72, priv.getEncoded().length);
            assertTrue(priv.getScalar().isPresent());
            assertEquals(56, priv.getScalar().get().length);
        }
    }

    @Nested
    @DisplayName("X25519 KeyAgreement Tests")
    class X25519KeyAgreementTests {

        @Test
        @DisplayName("Key agreement produces same shared secret")
        void testKeyAgreement() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();

            // Party 1 derives shared secret
            KeyAgreement ka1 = KeyAgreement.getInstance("X25519", "Glassless");
            ka1.init(kp1.getPrivate());
            ka1.doPhase(kp2.getPublic(), true);
            byte[] secret1 = ka1.generateSecret();

            // Party 2 derives shared secret
            KeyAgreement ka2 = KeyAgreement.getInstance("X25519", "Glassless");
            ka2.init(kp2.getPrivate());
            ka2.doPhase(kp1.getPublic(), true);
            byte[] secret2 = ka2.generateSecret();

            // Secrets should match
            assertNotNull(secret1);
            assertNotNull(secret2);
            assertEquals(32, secret1.length);
            assertEquals(32, secret2.length);
            assertArrayEquals(secret1, secret2);
        }

        @Test
        @DisplayName("XDH key agreement with X25519 keys")
        void testXDHKeyAgreement() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();

            KeyAgreement ka1 = KeyAgreement.getInstance("XDH", "Glassless");
            ka1.init(kp1.getPrivate());
            ka1.doPhase(kp2.getPublic(), true);
            byte[] secret1 = ka1.generateSecret();

            KeyAgreement ka2 = KeyAgreement.getInstance("XDH", "Glassless");
            ka2.init(kp2.getPrivate());
            ka2.doPhase(kp1.getPublic(), true);
            byte[] secret2 = ka2.generateSecret();

            assertArrayEquals(secret1, secret2);
        }

        @Test
        @DisplayName("Generate secret as SecretKey")
        void testGenerateSecretKey() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance("X25519", "Glassless");
            ka.init(kp1.getPrivate());
            ka.doPhase(kp2.getPublic(), true);
            javax.crypto.SecretKey secretKey = ka.generateSecret("AES");

            assertNotNull(secretKey);
            assertEquals("AES", secretKey.getAlgorithm());
            assertEquals(32, secretKey.getEncoded().length);
        }
    }

    @Nested
    @DisplayName("X448 KeyAgreement Tests")
    class X448KeyAgreementTests {

        @Test
        @DisplayName("X448 key agreement")
        void testKeyAgreement() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X448", "Glassless");
            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();

            KeyAgreement ka1 = KeyAgreement.getInstance("X448", "Glassless");
            ka1.init(kp1.getPrivate());
            ka1.doPhase(kp2.getPublic(), true);
            byte[] secret1 = ka1.generateSecret();

            KeyAgreement ka2 = KeyAgreement.getInstance("X448", "Glassless");
            ka2.init(kp2.getPrivate());
            ka2.doPhase(kp1.getPublic(), true);
            byte[] secret2 = ka2.generateSecret();

            assertNotNull(secret1);
            assertEquals(56, secret1.length);
            assertArrayEquals(secret1, secret2);
        }
    }

    @Nested
    @DisplayName("XDH KeyFactory Tests")
    class XDHKeyFactoryTests {

        @Test
        @DisplayName("Reconstruct X25519 keys from encoded")
        void testReconstructX25519Keys() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair original = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("XDH", "Glassless");

            // Reconstruct public key
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(original.getPublic().getEncoded());
            XECPublicKey reconstructedPub = (XECPublicKey) kf.generatePublic(pubSpec);
            assertArrayEquals(original.getPublic().getEncoded(), reconstructedPub.getEncoded());

            // Reconstruct private key
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(original.getPrivate().getEncoded());
            XECPrivateKey reconstructedPriv = (XECPrivateKey) kf.generatePrivate(privSpec);
            assertArrayEquals(original.getPrivate().getEncoded(), reconstructedPriv.getEncoded());
        }

        @Test
        @DisplayName("Get key specs from keys")
        void testGetKeySpecs() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("XDH", "Glassless");

            // Get X509 spec from public key
            X509EncodedKeySpec x509Spec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
            assertNotNull(x509Spec);
            assertArrayEquals(kp.getPublic().getEncoded(), x509Spec.getEncoded());

            // Get PKCS8 spec from private key
            PKCS8EncodedKeySpec pkcs8Spec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
            assertNotNull(pkcs8Spec);
            assertArrayEquals(kp.getPrivate().getEncoded(), pkcs8Spec.getEncoded());

            // Get XEC specs
            XECPublicKeySpec xecPubSpec = kf.getKeySpec(kp.getPublic(), XECPublicKeySpec.class);
            assertNotNull(xecPubSpec);
            assertNotNull(xecPubSpec.getU());

            XECPrivateKeySpec xecPrivSpec = kf.getKeySpec(kp.getPrivate(), XECPrivateKeySpec.class);
            assertNotNull(xecPrivSpec);
            assertEquals(32, xecPrivSpec.getScalar().length);
        }

        @Test
        @DisplayName("Translate keys from other provider")
        void testTranslateKeys() throws Exception {
            // Generate with default provider
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            KeyPair original = kpg.generateKeyPair();

            // Translate to Glassless
            KeyFactory kf = KeyFactory.getInstance("XDH", "Glassless");
            XECPublicKey translatedPub = (XECPublicKey) kf.translateKey(original.getPublic());
            XECPrivateKey translatedPriv = (XECPrivateKey) kf.translateKey(original.getPrivate());

            assertNotNull(translatedPub);
            assertNotNull(translatedPriv);

            // Use translated keys for key agreement
            KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair other = kpg2.generateKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance("X25519", "Glassless");
            ka.init(translatedPriv);
            ka.doPhase(other.getPublic(), true);
            byte[] secret = ka.generateSecret();

            assertNotNull(secret);
            assertEquals(32, secret.length);
        }
    }

    @Nested
    @DisplayName("Cross-provider Compatibility Tests")
    class CrossProviderTests {

        @Test
        @DisplayName("Glassless and SunEC produce same shared secret")
        void testCrossProviderKeyAgreement() throws Exception {
            // Generate key pairs
            KeyPairGenerator glasslessKpg = KeyPairGenerator.getInstance("X25519", "Glassless");
            KeyPair glasslessKp = glasslessKpg.generateKeyPair();

            KeyPairGenerator sunKpg = KeyPairGenerator.getInstance("X25519");
            KeyPair sunKp = sunKpg.generateKeyPair();

            // Glassless derives secret using Sun's public key
            KeyAgreement glasslessKa = KeyAgreement.getInstance("X25519", "Glassless");
            glasslessKa.init(glasslessKp.getPrivate());
            // Need to translate Sun's public key for Glassless
            KeyFactory kf = KeyFactory.getInstance("XDH", "Glassless");
            XECPublicKey translatedSunPub = (XECPublicKey) kf.generatePublic(
                new X509EncodedKeySpec(sunKp.getPublic().getEncoded()));
            glasslessKa.doPhase(translatedSunPub, true);
            byte[] glasslessSecret = glasslessKa.generateSecret();

            // Sun derives secret using Glassless' public key
            KeyAgreement sunKa = KeyAgreement.getInstance("X25519");
            sunKa.init(sunKp.getPrivate());
            KeyFactory sunKf = KeyFactory.getInstance("X25519");
            XECPublicKey translatedGlassPub = (XECPublicKey) sunKf.generatePublic(
                new X509EncodedKeySpec(glasslessKp.getPublic().getEncoded()));
            sunKa.doPhase(translatedGlassPub, true);
            byte[] sunSecret = sunKa.generateSecret();

            // Both should produce the same shared secret
            assertArrayEquals(sunSecret, glasslessSecret,
                "Cross-provider key agreement should produce same shared secret");
        }
    }
}
