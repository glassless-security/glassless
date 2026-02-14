package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class SignatureTest {

    private static KeyPair rsaKeyPair;
    private static KeyPair ecKeyPair;

    @BeforeAll
    public static void setUp() throws Exception {
        Security.addProvider(new GlaSSLessProvider());

        // Generate RSA key pair
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        rsaKeyPair = rsaKeyGen.generateKeyPair();

        // Generate EC key pair
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256);
        ecKeyPair = ecKeyGen.generateKeyPair();
    }

    @Nested
    @DisplayName("RSA Signatures (PKCS#1 v1.5)")
    class RSASignatureTests {

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"})
        void testRSASignAndVerify(String algorithm) throws Exception {
            Signature sig = Signature.getInstance(algorithm, "GlaSSLess");
            assertNotNull(sig);

            byte[] data = "Test data for RSA signature".getBytes();

            // Sign
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            assertNotNull(signature);
            assertTrue(signature.length > 0);

            // Verify
            sig.initVerify(rsaKeyPair.getPublic());
            sig.update(data);
            assertTrue(sig.verify(signature));
        }

        @ParameterizedTest(name = "{0} with modified data should fail verification")
        @ValueSource(strings = {"SHA256withRSA", "SHA512withRSA"})
        void testRSAVerifyFailsWithModifiedData(String algorithm) throws Exception {
            Signature sig = Signature.getInstance(algorithm, "GlaSSLess");

            byte[] data = "Test data for RSA signature".getBytes();

            // Sign
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            // Verify with modified data should fail
            byte[] modifiedData = "Modified test data".getBytes();
            sig.initVerify(rsaKeyPair.getPublic());
            sig.update(modifiedData);
            assertFalse(sig.verify(signature));
        }

        @Test
        @DisplayName("SHA256withRSA incremental update")
        void testRSAIncrementalUpdate() throws Exception {
            Signature sig = Signature.getInstance("SHA256withRSA", "GlaSSLess");

            // Sign with incremental updates
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update("Part 1 ".getBytes());
            sig.update("Part 2 ".getBytes());
            sig.update("Part 3".getBytes());
            byte[] signature = sig.sign();

            // Verify with single update
            sig.initVerify(rsaKeyPair.getPublic());
            sig.update("Part 1 Part 2 Part 3".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("ECDSA Signatures")
    class ECDSASignatureTests {

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"})
        void testECDSASignAndVerify(String algorithm) throws Exception {
            Signature sig = Signature.getInstance(algorithm, "GlaSSLess");
            assertNotNull(sig);

            byte[] data = "Test data for ECDSA signature".getBytes();

            // Sign
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            assertNotNull(signature);
            assertTrue(signature.length > 0);

            // Verify
            sig.initVerify(ecKeyPair.getPublic());
            sig.update(data);
            assertTrue(sig.verify(signature));
        }

        @ParameterizedTest(name = "{0} with modified data should fail verification")
        @ValueSource(strings = {"SHA256withECDSA", "SHA512withECDSA"})
        void testECDSAVerifyFailsWithModifiedData(String algorithm) throws Exception {
            Signature sig = Signature.getInstance(algorithm, "GlaSSLess");

            byte[] data = "Test data for ECDSA signature".getBytes();

            // Sign
            sig.initSign(ecKeyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            // Verify with modified data should fail
            byte[] modifiedData = "Modified test data".getBytes();
            sig.initVerify(ecKeyPair.getPublic());
            sig.update(modifiedData);
            assertFalse(sig.verify(signature));
        }

        @Test
        @DisplayName("SHA256withECDSA incremental update")
        void testECDSAIncrementalUpdate() throws Exception {
            Signature sig = Signature.getInstance("SHA256withECDSA", "GlaSSLess");

            // Sign with incremental updates
            sig.initSign(ecKeyPair.getPrivate());
            sig.update("Part 1 ".getBytes());
            sig.update("Part 2 ".getBytes());
            sig.update("Part 3".getBytes());
            byte[] signature = sig.sign();

            // Verify with single update
            sig.initVerify(ecKeyPair.getPublic());
            sig.update("Part 1 Part 2 Part 3".getBytes());
            assertTrue(sig.verify(signature));
        }
    }

    @Nested
    @DisplayName("RSA-PSS Signatures")
    class RSAPSSSignatureTests {

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"SHA1withRSAandMGF1", "SHA224withRSAandMGF1", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1"})
        void testRSAPSSSignAndVerify(String algorithm) throws Exception {
            Signature sig = Signature.getInstance(algorithm, "GlaSSLess");
            assertNotNull(sig);

            byte[] data = "Test data for RSA-PSS signature".getBytes();

            // Sign
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            assertNotNull(signature);
            assertTrue(signature.length > 0);

            // Verify
            sig.initVerify(rsaKeyPair.getPublic());
            sig.update(data);
            assertTrue(sig.verify(signature));
        }

        @ParameterizedTest(name = "{0} with modified data should fail verification")
        @ValueSource(strings = {"SHA256withRSAandMGF1", "SHA512withRSAandMGF1"})
        void testRSAPSSVerifyFailsWithModifiedData(String algorithm) throws Exception {
            Signature sig = Signature.getInstance(algorithm, "GlaSSLess");

            byte[] data = "Test data for RSA-PSS signature".getBytes();

            // Sign
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(data);
            byte[] signature = sig.sign();

            // Verify with modified data should fail
            byte[] modifiedData = "Modified test data".getBytes();
            sig.initVerify(rsaKeyPair.getPublic());
            sig.update(modifiedData);
            assertFalse(sig.verify(signature));
        }
    }
}
