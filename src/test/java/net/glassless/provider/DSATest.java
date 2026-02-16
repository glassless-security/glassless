package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class DSATest {

    private static KeyPair dsaKeyPair;

    @BeforeAll
    public static void setUp() throws Exception {
        Security.addProvider(new GlaSSLessProvider());

        // Generate DSA key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        dsaKeyPair = keyGen.generateKeyPair();
    }

    @Disabled
    @Nested
    @DisplayName("DSA KeyPairGenerator")
    class DSAKeyPairGeneratorTests {

        @Test
        @DisplayName("Generate DSA key pair with 2048 bits")
        void testGenerateKeyPair2048() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "GlaSSLess");
            keyGen.initialize(2048);

            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());
           assertInstanceOf(DSAPublicKey.class, keyPair.getPublic());
           assertInstanceOf(DSAPrivateKey.class, keyPair.getPrivate());
        }

        @Test
        @DisplayName("Generate DSA key pair with 3072 bits")
        void testGenerateKeyPair3072() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "GlaSSLess");
            keyGen.initialize(3072);

            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull(keyPair);
           assertInstanceOf(DSAPublicKey.class, keyPair.getPublic());
           assertInstanceOf(DSAPrivateKey.class, keyPair.getPrivate());
        }
    }

    @Nested
    @DisplayName("DSA KeyFactory")
    class DSAKeyFactoryTests {

        @Test
        @DisplayName("Generate public key from X509EncodedKeySpec")
        void testGeneratePublicFromX509() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");
            assertNotNull(kf);

            byte[] encoded = dsaKeyPair.getPublic().getEncoded();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
           assertInstanceOf(DSAPublicKey.class, publicKey);
            assertArrayEquals(encoded, publicKey.getEncoded());
        }

        @Test
        @DisplayName("Generate private key from PKCS8EncodedKeySpec")
        void testGeneratePrivateFromPKCS8() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");

            byte[] encoded = dsaKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
           assertInstanceOf(DSAPrivateKey.class, privateKey);
            assertArrayEquals(encoded, privateKey.getEncoded());
        }

        @Test
        @DisplayName("Generate public key from DSAPublicKeySpec")
        void testGeneratePublicFromDSASpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");

            DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyPair.getPublic();
            DSAPublicKeySpec spec = new DSAPublicKeySpec(
                dsaPub.getY(),
                dsaPub.getParams().getP(),
                dsaPub.getParams().getQ(),
                dsaPub.getParams().getG()
            );

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
           assertInstanceOf(DSAPublicKey.class, publicKey);

            DSAPublicKey generatedKey = (DSAPublicKey) publicKey;
            assertEquals(dsaPub.getY(), generatedKey.getY());
        }

        @Test
        @DisplayName("Generate private key from DSAPrivateKeySpec")
        void testGeneratePrivateFromDSASpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");

            DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyPair.getPrivate();
            DSAPrivateKeySpec spec = new DSAPrivateKeySpec(
                dsaPriv.getX(),
                dsaPriv.getParams().getP(),
                dsaPriv.getParams().getQ(),
                dsaPriv.getParams().getG()
            );

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
           assertInstanceOf(DSAPrivateKey.class, privateKey);

            DSAPrivateKey generatedKey = (DSAPrivateKey) privateKey;
            assertEquals(dsaPriv.getX(), generatedKey.getX());
        }

        @Test
        @DisplayName("Get X509EncodedKeySpec from DSA public key")
        void testGetX509SpecFromPublic() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");

            X509EncodedKeySpec spec = kf.getKeySpec(dsaKeyPair.getPublic(), X509EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(dsaKeyPair.getPublic().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Get PKCS8EncodedKeySpec from DSA private key")
        void testGetPKCS8SpecFromPrivate() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");

            PKCS8EncodedKeySpec spec = kf.getKeySpec(dsaKeyPair.getPrivate(), PKCS8EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(dsaKeyPair.getPrivate().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Translate DSA key")
        void testTranslateKey() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("DSA", "GlaSSLess");

            PublicKey translated = (PublicKey) kf.translateKey(dsaKeyPair.getPublic());

            assertNotNull(translated);
           assertInstanceOf(DSAPublicKey.class, translated);
            assertArrayEquals(dsaKeyPair.getPublic().getEncoded(), translated.getEncoded());
        }
    }

    @Nested
    @DisplayName("DSA Signatures")
    class DSASignatureTests {

        private final byte[] testData = "Test data for DSA signature".getBytes();

        @Test
        @DisplayName("SHA1withDSA sign and verify")
        void testSHA1withDSA() throws Exception {
            Signature sig = Signature.getInstance("SHA1withDSA", "GlaSSLess");

            // Sign
            sig.initSign(dsaKeyPair.getPrivate());
            sig.update(testData);
            byte[] signature = sig.sign();

            assertNotNull(signature);
            assertTrue(signature.length > 0);

            // Verify
            sig.initVerify(dsaKeyPair.getPublic());
            sig.update(testData);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("SHA256withDSA sign and verify")
        void testSHA256withDSA() throws Exception {
            Signature sig = Signature.getInstance("SHA256withDSA", "GlaSSLess");

            // Sign
            sig.initSign(dsaKeyPair.getPrivate());
            sig.update(testData);
            byte[] signature = sig.sign();

            assertNotNull(signature);

            // Verify
            sig.initVerify(dsaKeyPair.getPublic());
            sig.update(testData);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("SHA384withDSA sign and verify")
        void testSHA384withDSA() throws Exception {
            Signature sig = Signature.getInstance("SHA384withDSA", "GlaSSLess");

            sig.initSign(dsaKeyPair.getPrivate());
            sig.update(testData);
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(dsaKeyPair.getPublic());
            sig.update(testData);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("SHA512withDSA sign and verify")
        void testSHA512withDSA() throws Exception {
            Signature sig = Signature.getInstance("SHA512withDSA", "GlaSSLess");

            sig.initSign(dsaKeyPair.getPrivate());
            sig.update(testData);
            byte[] signature = sig.sign();

            assertNotNull(signature);

            sig.initVerify(dsaKeyPair.getPublic());
            sig.update(testData);
            assertTrue(sig.verify(signature));
        }

        @Test
        @DisplayName("DSA signature interoperability with default provider")
        void testDSAInteroperability() throws Exception {
            // Sign with GlaSSLess
            Signature glasslessSig = Signature.getInstance("SHA256withDSA", "GlaSSLess");
            glasslessSig.initSign(dsaKeyPair.getPrivate());
            glasslessSig.update(testData);
            byte[] signature = glasslessSig.sign();

            // Verify with default provider
            Signature defaultSig = Signature.getInstance("SHA256withDSA");
            defaultSig.initVerify(dsaKeyPair.getPublic());
            defaultSig.update(testData);
            assertTrue(defaultSig.verify(signature), "GlaSSLess signature should be verifiable by default provider");
        }

        @Test
        @DisplayName("DSA signature with GlaSSLess-generated keys")
        void testDSAWithGlaSSLessKeys() throws Exception {
            // Generate keys with GlaSSLess
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "GlaSSLess");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Sign
            Signature sig = Signature.getInstance("SHA256withDSA", "GlaSSLess");
            sig.initSign(keyPair.getPrivate());
            sig.update(testData);
            byte[] signature = sig.sign();

            // Verify
            sig.initVerify(keyPair.getPublic());
            sig.update(testData);
            assertTrue(sig.verify(signature));
        }
    }
}
