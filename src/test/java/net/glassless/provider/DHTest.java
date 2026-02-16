package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@Disabled
public class DHTest {

    private static KeyPair dhKeyPair;

    @BeforeAll
    public static void setUp() throws Exception {
        Security.addProvider(new GlaSSLessProvider());

        // Generate DH key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048);
        dhKeyPair = keyGen.generateKeyPair();
    }

    @Nested
    @DisplayName("DH KeyPairGenerator")
    class DHKeyPairGeneratorTests {

        @Test
        @DisplayName("Generate DH key pair with 2048 bits")
        void testGenerateKeyPair2048() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "GlaSSLess");
            keyGen.initialize(2048);

            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());
            assertTrue(keyPair.getPublic() instanceof DHPublicKey);
            assertTrue(keyPair.getPrivate() instanceof DHPrivateKey);
        }
    }

    @Nested
    @DisplayName("DH KeyFactory")
    class DHKeyFactoryTests {

        @Test
        @DisplayName("Generate public key from X509EncodedKeySpec")
        void testGeneratePublicFromX509() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");
            assertNotNull(kf);

            byte[] encoded = dhKeyPair.getPublic().getEncoded();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof DHPublicKey);
            assertArrayEquals(encoded, publicKey.getEncoded());
        }

        @Test
        @DisplayName("Generate private key from PKCS8EncodedKeySpec")
        void testGeneratePrivateFromPKCS8() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");

            byte[] encoded = dhKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof DHPrivateKey);
            assertArrayEquals(encoded, privateKey.getEncoded());
        }

        @Test
        @DisplayName("Generate public key from DHPublicKeySpec")
        void testGeneratePublicFromDHSpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");

            DHPublicKey dhPub = (DHPublicKey) dhKeyPair.getPublic();
            DHPublicKeySpec spec = new DHPublicKeySpec(
                dhPub.getY(),
                dhPub.getParams().getP(),
                dhPub.getParams().getG()
            );

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof DHPublicKey);

            DHPublicKey generatedKey = (DHPublicKey) publicKey;
            assertEquals(dhPub.getY(), generatedKey.getY());
        }

        @Test
        @DisplayName("Generate private key from DHPrivateKeySpec")
        void testGeneratePrivateFromDHSpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");

            DHPrivateKey dhPriv = (DHPrivateKey) dhKeyPair.getPrivate();
            DHPrivateKeySpec spec = new DHPrivateKeySpec(
                dhPriv.getX(),
                dhPriv.getParams().getP(),
                dhPriv.getParams().getG()
            );

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof DHPrivateKey);

            DHPrivateKey generatedKey = (DHPrivateKey) privateKey;
            assertEquals(dhPriv.getX(), generatedKey.getX());
        }

        @Test
        @DisplayName("Get X509EncodedKeySpec from DH public key")
        void testGetX509SpecFromPublic() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");

            X509EncodedKeySpec spec = kf.getKeySpec(dhKeyPair.getPublic(), X509EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(dhKeyPair.getPublic().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Get PKCS8EncodedKeySpec from DH private key")
        void testGetPKCS8SpecFromPrivate() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");

            PKCS8EncodedKeySpec spec = kf.getKeySpec(dhKeyPair.getPrivate(), PKCS8EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(dhKeyPair.getPrivate().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Translate DH key")
        void testTranslateKey() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DH", "GlaSSLess");

            PublicKey translated = (PublicKey) kf.translateKey(dhKeyPair.getPublic());

            assertNotNull(translated);
            assertTrue(translated instanceof DHPublicKey);
            assertArrayEquals(dhKeyPair.getPublic().getEncoded(), translated.getEncoded());
        }
    }

    @Nested
    @DisplayName("DH Key Agreement")
    class DHKeyAgreementTests {

        @Test
        @DisplayName("DH key agreement basic test")
        void testDHKeyAgreement() throws Exception {
            // Generate two DH key pairs (Alice and Bob) with same parameters
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(2048);

            KeyPair aliceKeyPair = keyGen.generateKeyPair();

            // Bob needs to use the same DH parameters
            DHPublicKey alicePubKey = (DHPublicKey) aliceKeyPair.getPublic();
            keyGen.initialize(alicePubKey.getParams());
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("DH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob computes the shared secret
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("DH", "GlaSSLess");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            // Both should compute the same shared secret
            assertNotNull(aliceSharedSecret);
            assertNotNull(bobSharedSecret);
            assertTrue(aliceSharedSecret.length > 0);
            assertArrayEquals(aliceSharedSecret, bobSharedSecret);
        }

        @Test
        @DisplayName("DH key agreement generates different secrets with different keys")
        void testDHDifferentKeys() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(2048);

            KeyPair aliceKeyPair = keyGen.generateKeyPair();

            DHPublicKey alicePubKey = (DHPublicKey) aliceKeyPair.getPublic();
            keyGen.initialize(alicePubKey.getParams());
            KeyPair bobKeyPair = keyGen.generateKeyPair();
            KeyPair charlieKeyPair = keyGen.generateKeyPair();

            // Alice-Bob shared secret
            KeyAgreement ka1 = KeyAgreement.getInstance("DH", "GlaSSLess");
            ka1.init(aliceKeyPair.getPrivate());
            ka1.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceBobSecret = ka1.generateSecret();

            // Alice-Charlie shared secret
            KeyAgreement ka2 = KeyAgreement.getInstance("DH", "GlaSSLess");
            ka2.init(aliceKeyPair.getPrivate());
            ka2.doPhase(charlieKeyPair.getPublic(), true);
            byte[] aliceCharlieSecret = ka2.generateSecret();

            // The two shared secrets should be different
            assertTrue(!Arrays.equals(aliceBobSecret, aliceCharlieSecret),
                    "Shared secrets with different parties should be different");
        }

        @Test
        @DisplayName("DH generateSecret with algorithm produces SecretKey")
        void testDHGenerateSecretKey() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(2048);

            KeyPair aliceKeyPair = keyGen.generateKeyPair();

            DHPublicKey alicePubKey = (DHPublicKey) aliceKeyPair.getPublic();
            keyGen.initialize(alicePubKey.getParams());
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret as an AES key
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("DH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            SecretKey aliceSecretKey = aliceKeyAgreement.generateSecret("AES");

            assertNotNull(aliceSecretKey);
            assertEquals("AES", aliceSecretKey.getAlgorithm());
            assertTrue(aliceSecretKey.getEncoded().length > 0);
        }

        @Test
        @DisplayName("DH key agreement with GlaSSLess KeyPairGenerator")
        void testDHWithGlaSSLessKeyGen() throws Exception {
            // Generate Alice's keys with GlaSSLess
            KeyPairGenerator glasslessKeyGen = KeyPairGenerator.getInstance("DH", "GlaSSLess");
            glasslessKeyGen.initialize(2048);
            KeyPair aliceKeyPair = glasslessKeyGen.generateKeyPair();

            // Generate Bob's keys using default provider with Alice's parameters
            // (GlaSSLess DHKeyPairGenerator extracts key size from DHParameterSpec,
            // so we use default provider to ensure matching parameters)
            DHPublicKey alicePubKey = (DHPublicKey) aliceKeyPair.getPublic();
            KeyPairGenerator defaultKeyGen = KeyPairGenerator.getInstance("DH");
            defaultKeyGen.initialize(alicePubKey.getParams());
            KeyPair bobKeyPair = defaultKeyGen.generateKeyPair();

            // Alice computes the shared secret with GlaSSLess
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("DH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob computes the shared secret with GlaSSLess
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("DH", "GlaSSLess");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            assertNotNull(aliceSharedSecret);
            assertNotNull(bobSharedSecret);
            assertArrayEquals(aliceSharedSecret, bobSharedSecret);
        }

        @Test
        @DisplayName("DH interoperability with default provider")
        void testDHInteroperability() throws Exception {
            // Generate keys with default provider
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(2048);

            KeyPair aliceKeyPair = keyGen.generateKeyPair();

            DHPublicKey alicePubKey = (DHPublicKey) aliceKeyPair.getPublic();
            keyGen.initialize(alicePubKey.getParams());
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice uses GlaSSLess
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("DH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob uses default provider
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("DH");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            // Both should compute the same shared secret
            assertArrayEquals(aliceSharedSecret, bobSharedSecret,
                    "GlaSSLess and default provider should produce the same shared secret");
        }
    }
}
