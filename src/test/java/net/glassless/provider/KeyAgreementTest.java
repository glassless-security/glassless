package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class KeyAgreementTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("ECDH Key Agreement")
    class ECDHKeyAgreementTests {

        @Test
        @DisplayName("ECDH key agreement with P-256 curve")
        void testECDHWithP256() throws Exception {
            // Generate two EC key pairs (Alice and Bob)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob computes the shared secret
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            // Both should compute the same shared secret
            assertNotNull(aliceSharedSecret);
            assertNotNull(bobSharedSecret);
            assertEquals(32, aliceSharedSecret.length); // P-256 produces 32-byte secret
            assertArrayEquals(aliceSharedSecret, bobSharedSecret);
        }

        @Test
        @DisplayName("ECDH key agreement with P-384 curve")
        void testECDHWithP384() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp384r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob computes the shared secret
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            assertNotNull(aliceSharedSecret);
            assertEquals(48, aliceSharedSecret.length); // P-384 produces 48-byte secret
            assertArrayEquals(aliceSharedSecret, bobSharedSecret);
        }

        @Test
        @DisplayName("ECDH key agreement with P-521 curve")
        void testECDHWithP521() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp521r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob computes the shared secret
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            assertNotNull(aliceSharedSecret);
            assertEquals(66, aliceSharedSecret.length); // P-521 produces 66-byte secret
            assertArrayEquals(aliceSharedSecret, bobSharedSecret);
        }

        @Test
        @DisplayName("ECDH key agreement generates different secrets with different keys")
        void testECDHDifferentKeys() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();
            KeyPair charlieKeyPair = keyGen.generateKeyPair();

            // Alice-Bob shared secret
            KeyAgreement ka1 = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            ka1.init(aliceKeyPair.getPrivate());
            ka1.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceBobSecret = ka1.generateSecret();

            // Alice-Charlie shared secret
            KeyAgreement ka2 = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            ka2.init(aliceKeyPair.getPrivate());
            ka2.doPhase(charlieKeyPair.getPublic(), true);
            byte[] aliceCharlieSecret = ka2.generateSecret();

            // The two shared secrets should be different
            assertTrue(!Arrays.equals(aliceBobSecret, aliceCharlieSecret),
                    "Shared secrets with different parties should be different");
        }

        @Test
        @DisplayName("ECDH generateSecret with algorithm produces SecretKey")
        void testECDHGenerateSecretKey() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret as an AES key
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            SecretKey aliceSecretKey = aliceKeyAgreement.generateSecret("AES");

            assertNotNull(aliceSecretKey);
            assertEquals("AES", aliceSecretKey.getAlgorithm());
            assertEquals(32, aliceSecretKey.getEncoded().length);
        }

        @Test
        @DisplayName("ECDH generateSecret into buffer")
        void testECDHGenerateSecretToBuffer() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);

            byte[] buffer = new byte[64];
            int len = aliceKeyAgreement.generateSecret(buffer, 0);

            assertEquals(32, len);
        }

        @Test
        @DisplayName("ECDH key agreement reusability")
        void testECDHReusability() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();
            KeyPair charlieKeyPair = keyGen.generateKeyPair();

            // Alice can perform multiple key agreements
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");

            // First agreement with Bob
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] secretWithBob = aliceKeyAgreement.generateSecret();

            // Second agreement with Charlie (reusing same KeyAgreement object)
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(charlieKeyPair.getPublic(), true);
            byte[] secretWithCharlie = aliceKeyAgreement.generateSecret();

            assertNotNull(secretWithBob);
            assertNotNull(secretWithCharlie);
            assertTrue(!Arrays.equals(secretWithBob, secretWithCharlie));
        }

        @Test
        @DisplayName("ECDH with GlaSSLess KeyPairGenerator")
        void testECDHWithGlaSSLessKeyGen() throws Exception {
            // Use GlaSSLess provider for key generation as well
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice computes the shared secret
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob computes the shared secret
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            assertNotNull(aliceSharedSecret);
            assertNotNull(bobSharedSecret);
            assertArrayEquals(aliceSharedSecret, bobSharedSecret);
        }

        @Test
        @DisplayName("ECDH interoperability with default provider")
        void testECDHInteroperability() throws Exception {
            // Generate keys with default provider
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            // Alice uses GlaSSLess
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "GlaSSLess");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // Bob uses default provider
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            // Both should compute the same shared secret
            assertArrayEquals(aliceSharedSecret, bobSharedSecret,
                    "GlaSSLess and default provider should produce the same shared secret");
        }
    }
}
