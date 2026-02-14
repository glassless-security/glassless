package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class KeyPairGeneratorTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("RSA KeyPairGenerator")
    class RSAKeyPairGeneratorTests {

        @ParameterizedTest(name = "RSA {0}-bit key")
        @ValueSource(ints = {1024, 2048, 3072, 4096})
        void testRSAKeyGeneration(int keySize) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "GlaSSLess");
            assertNotNull(keyGen);

            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());

            assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
            assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            assertEquals(keySize, publicKey.getModulus().bitLength());
        }

        @Test
        @DisplayName("RSA default key size")
        void testRSADefaultKeySize() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "GlaSSLess");
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            assertEquals(2048, publicKey.getModulus().bitLength());
        }

        @Test
        @DisplayName("RSA with RSAKeyGenParameterSpec")
        void testRSAWithParameterSpec() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "GlaSSLess");
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537));
            keyGen.initialize(spec);

            KeyPair keyPair = keyGen.generateKeyPair();
            assertNotNull(keyPair);

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            assertEquals(2048, publicKey.getModulus().bitLength());
        }

        @Test
        @DisplayName("RSA key pair can be used for signing")
        void testRSAKeyPairUsedForSigning() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "GlaSSLess");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Use the generated keys with our signature implementation
            Signature sig = Signature.getInstance("SHA256withRSA", "GlaSSLess");
            byte[] data = "Test data for signing".getBytes();

            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            sig.initVerify(keyPair.getPublic());
            sig.update(data);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Generated RSA keys are unique")
        void testRSAKeyUniqueness() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "GlaSSLess");
            keyGen.initialize(2048);

            KeyPair keyPair1 = keyGen.generateKeyPair();
            KeyPair keyPair2 = keyGen.generateKeyPair();

            RSAPublicKey pub1 = (RSAPublicKey) keyPair1.getPublic();
            RSAPublicKey pub2 = (RSAPublicKey) keyPair2.getPublic();

            // Different key pairs should have different moduli
            assertTrue(!pub1.getModulus().equals(pub2.getModulus()));
        }
    }

    @Nested
    @DisplayName("EC KeyPairGenerator")
    class ECKeyPairGeneratorTests {

        @ParameterizedTest(name = "EC {0}-bit key")
        @ValueSource(ints = {256, 384, 521})
        void testECKeyGenerationBySize(int keySize) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            assertNotNull(keyGen);

            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());

            assertTrue(keyPair.getPublic() instanceof ECPublicKey);
            assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
        }

        @ParameterizedTest(name = "EC curve {0}")
        @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
        void testECKeyGenerationByCurveName(String curveName) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            keyGen.initialize(new ECGenParameterSpec(curveName));

            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertTrue(keyPair.getPublic() instanceof ECPublicKey);
            assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
        }

        @Test
        @DisplayName("EC default curve (P-256)")
        void testECDefaultCurve() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        }

        @Test
        @DisplayName("EC with P-256 alias")
        void testECWithP256Alias() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            keyGen.initialize(new ECGenParameterSpec("P-256"));

            KeyPair keyPair = keyGen.generateKeyPair();
            assertNotNull(keyPair);
        }

        @Test
        @DisplayName("EC key pair can be used for ECDSA signing")
        void testECKeyPairUsedForSigning() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Use the generated keys with our signature implementation
            Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
            byte[] data = "Test data for ECDSA signing".getBytes();

            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            sig.initVerify(keyPair.getPublic());
            sig.update(data);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("Generated EC keys are unique")
        void testECKeyUniqueness() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
            keyGen.initialize(256);

            KeyPair keyPair1 = keyGen.generateKeyPair();
            KeyPair keyPair2 = keyGen.generateKeyPair();

            ECPrivateKey priv1 = (ECPrivateKey) keyPair1.getPrivate();
            ECPrivateKey priv2 = (ECPrivateKey) keyPair2.getPrivate();

            // Different key pairs should have different private key values
            assertTrue(!priv1.getS().equals(priv2.getS()));
        }
    }
}
