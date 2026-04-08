package net.glassless.provider;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.Assumptions;
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
            Assumptions.assumeFalse(keySize < 2048 && FIPSStatus.isFIPSEnabled(),
               "RSA keys smaller than 2048 bits are not allowed in FIPS mode");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            assertNotNull(keyGen);

            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());

           assertInstanceOf(RSAPublicKey.class, keyPair.getPublic());
           assertInstanceOf(RSAPrivateKey.class, keyPair.getPrivate());

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            assertEquals(keySize, publicKey.getModulus().bitLength());
        }

        @Test
        @DisplayName("RSA default key size")
        void testRSADefaultKeySize() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            assertEquals(2048, publicKey.getModulus().bitLength());
        }

        @Test
        @DisplayName("RSA with RSAKeyGenParameterSpec")
        void testRSAWithParameterSpec() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Use the generated keys with our signature implementation
            Signature sig = Signature.getInstance("SHA256withRSA", PROVIDER_NAME);
            byte[] data = "Test data for signing".getBytes(StandardCharsets.UTF_8);

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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            keyGen.initialize(2048);

            KeyPair keyPair1 = keyGen.generateKeyPair();
            KeyPair keyPair2 = keyGen.generateKeyPair();

            RSAPublicKey pub1 = (RSAPublicKey) keyPair1.getPublic();
            RSAPublicKey pub2 = (RSAPublicKey) keyPair2.getPublic();

            // Different key pairs should have different moduli
           assertFalse(pub1.getModulus().equals(pub2.getModulus()));
        }
    }

    @Nested
    @DisplayName("EC KeyPairGenerator")
    class ECKeyPairGeneratorTests {

        @ParameterizedTest(name = "EC {0}-bit key")
        @ValueSource(ints = {256, 384, 521})
        void testECKeyGenerationBySize(int keySize) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            assertNotNull(keyGen);

            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());

           assertInstanceOf(ECPublicKey.class, keyPair.getPublic());
           assertInstanceOf(ECPrivateKey.class, keyPair.getPrivate());
        }

        @ParameterizedTest(name = "EC curve {0}")
        @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
        void testECKeyGenerationByCurveName(String curveName) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            keyGen.initialize(new ECGenParameterSpec(curveName));

            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
           assertInstanceOf(ECPublicKey.class, keyPair.getPublic());
           assertInstanceOf(ECPrivateKey.class, keyPair.getPrivate());
        }

        @Test
        @DisplayName("EC default curve (P-256)")
        void testECDefaultCurve() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
           assertInstanceOf(ECPublicKey.class, keyPair.getPublic());
        }

        @Test
        @DisplayName("EC with P-256 alias")
        void testECWithP256Alias() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            keyGen.initialize(new ECGenParameterSpec("P-256"));

            KeyPair keyPair = keyGen.generateKeyPair();
            assertNotNull(keyPair);
        }

        @Test
        @DisplayName("EC key pair can be used for ECDSA signing")
        void testECKeyPairUsedForSigning() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Use the generated keys with our signature implementation
            Signature sig = Signature.getInstance("SHA256withECDSA", PROVIDER_NAME);
            byte[] data = "Test data for ECDSA signing".getBytes(StandardCharsets.UTF_8);

            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            sig.initVerify(keyPair.getPublic());
            sig.update(data);
            assertTrue(sig.verify(signature));
        }

        @ParameterizedTest(name = "EC with ECParameterSpec from {0} curve")
        @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
        @DisplayName("EC with ECParameterSpec (JSSE NamedCurve compatibility)")
        void testECKeyGenerationWithECParameterSpec(String curveName) throws Exception {
            // JSSE passes sun.security.util.NamedCurve (extends ECParameterSpec), not ECGenParameterSpec.
            // Simulate this by extracting ECParameterSpec from a JDK-generated key.
            KeyPairGenerator jdkKeyGen = KeyPairGenerator.getInstance("EC", "SunEC");
            jdkKeyGen.initialize(new ECGenParameterSpec(curveName));
            KeyPair jdkKeyPair = jdkKeyGen.generateKeyPair();
            ECParameterSpec ecParams = ((ECPublicKey) jdkKeyPair.getPublic()).getParams();

            // Initialize GlaSSLess EC KeyPairGenerator with ECParameterSpec (not ECGenParameterSpec)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            keyGen.initialize(ecParams);

            KeyPair keyPair = keyGen.generateKeyPair();
            assertNotNull(keyPair);
            assertInstanceOf(ECPublicKey.class, keyPair.getPublic());
            assertInstanceOf(ECPrivateKey.class, keyPair.getPrivate());

            // Verify the generated key uses the same curve
            ECPublicKey generatedPub = (ECPublicKey) keyPair.getPublic();
            assertEquals(ecParams.getCurve().getField().getFieldSize(),
                generatedPub.getParams().getCurve().getField().getFieldSize());
        }

        @Test
        @DisplayName("Generated EC keys are unique")
        void testECKeyUniqueness() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            keyGen.initialize(256);

            KeyPair keyPair1 = keyGen.generateKeyPair();
            KeyPair keyPair2 = keyGen.generateKeyPair();

            ECPrivateKey priv1 = (ECPrivateKey) keyPair1.getPrivate();
            ECPrivateKey priv2 = (ECPrivateKey) keyPair2.getPrivate();

            // Different key pairs should have different private key values
            assertFalse(priv1.getS().equals(priv2.getS()));
        }
    }

    @Nested
    @DisplayName("KeyFactory Delegation")
    class KeyFactoryDelegationTests {

        @Test
        @DisplayName("EC KeyFactory does not recurse when GlaSSLess is highest-priority provider")
        void testECKeyFactoryNoRecursion() throws Exception {
            // Generate a key pair — this exercises getDelegateKeyFactory internally
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Re-encode and reconstruct through our KeyFactory — should not StackOverflow
            KeyFactory kf = KeyFactory.getInstance("EC", PROVIDER_NAME);
            ECPublicKey pub = (ECPublicKey) kf.generatePublic(
                new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
            ECPrivateKey priv = (ECPrivateKey) kf.generatePrivate(
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

            assertNotNull(pub);
            assertNotNull(priv);
        }

        @Test
        @DisplayName("RSA KeyFactory does not recurse when GlaSSLess is highest-priority provider")
        void testRSAKeyFactoryNoRecursion() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("RSA", PROVIDER_NAME);
            RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(
                new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
            RSAPrivateKey priv = (RSAPrivateKey) kf.generatePrivate(
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

            assertNotNull(pub);
            assertNotNull(priv);
        }
    }
}
