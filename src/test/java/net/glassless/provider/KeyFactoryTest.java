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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class KeyFactoryTest {

    private static KeyPair rsaKeyPair;
    private static KeyPair ecKeyPair;

    @BeforeAll
    public static void setUp() throws Exception {
        Security.addProvider(new GlasslessProvider());

        // Generate RSA key pair for testing
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        rsaKeyPair = rsaKeyGen.generateKeyPair();

        // Generate EC key pair for testing
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256);
        ecKeyPair = ecKeyGen.generateKeyPair();
    }

    @Nested
    @DisplayName("RSA KeyFactory")
    class RSAKeyFactoryTests {

        @Test
        @DisplayName("Generate public key from X509EncodedKeySpec")
        void testGeneratePublicFromX509() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");
            assertNotNull(kf);

            byte[] encoded = rsaKeyPair.getPublic().getEncoded();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof RSAPublicKey);
            assertArrayEquals(encoded, publicKey.getEncoded());
        }

        @Test
        @DisplayName("Generate private key from PKCS8EncodedKeySpec")
        void testGeneratePrivateFromPKCS8() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            byte[] encoded = rsaKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof RSAPrivateCrtKey);
            assertArrayEquals(encoded, privateKey.getEncoded());
        }

        @Test
        @DisplayName("Generate public key from RSAPublicKeySpec")
        void testGeneratePublicFromRSASpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
            RSAPublicKeySpec spec = new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent());

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof RSAPublicKey);

            RSAPublicKey generatedKey = (RSAPublicKey) publicKey;
            assertEquals(rsaPub.getModulus(), generatedKey.getModulus());
            assertEquals(rsaPub.getPublicExponent(), generatedKey.getPublicExponent());
        }

        @Test
        @DisplayName("Generate private key from RSAPrivateCrtKeySpec")
        void testGeneratePrivateFromRSACrtSpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
            RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                rsaPriv.getModulus(),
                rsaPriv.getPublicExponent(),
                rsaPriv.getPrivateExponent(),
                rsaPriv.getPrimeP(),
                rsaPriv.getPrimeQ(),
                rsaPriv.getPrimeExponentP(),
                rsaPriv.getPrimeExponentQ(),
                rsaPriv.getCrtCoefficient()
            );

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof RSAPrivateCrtKey);
        }

        @Test
        @DisplayName("Get X509EncodedKeySpec from RSA public key")
        void testGetX509SpecFromPublic() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            X509EncodedKeySpec spec = kf.getKeySpec(rsaKeyPair.getPublic(), X509EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(rsaKeyPair.getPublic().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Get RSAPublicKeySpec from RSA public key")
        void testGetRSASpecFromPublic() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            RSAPublicKeySpec spec = kf.getKeySpec(rsaKeyPair.getPublic(), RSAPublicKeySpec.class);

            assertNotNull(spec);
            RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
            assertEquals(rsaPub.getModulus(), spec.getModulus());
            assertEquals(rsaPub.getPublicExponent(), spec.getPublicExponent());
        }

        @Test
        @DisplayName("Get PKCS8EncodedKeySpec from RSA private key")
        void testGetPKCS8SpecFromPrivate() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            PKCS8EncodedKeySpec spec = kf.getKeySpec(rsaKeyPair.getPrivate(), PKCS8EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(rsaKeyPair.getPrivate().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Translate RSA key")
        void testTranslateKey() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA", "Glassless");

            PublicKey translated = (PublicKey) kf.translateKey(rsaKeyPair.getPublic());

            assertNotNull(translated);
            assertTrue(translated instanceof RSAPublicKey);
            assertArrayEquals(rsaKeyPair.getPublic().getEncoded(), translated.getEncoded());
        }
    }

    @Nested
    @DisplayName("EC KeyFactory")
    class ECKeyFactoryTests {

        @Test
        @DisplayName("Generate public key from X509EncodedKeySpec")
        void testGeneratePublicFromX509() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");
            assertNotNull(kf);

            byte[] encoded = ecKeyPair.getPublic().getEncoded();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof ECPublicKey);
            assertArrayEquals(encoded, publicKey.getEncoded());
        }

        @Test
        @DisplayName("Generate private key from PKCS8EncodedKeySpec")
        void testGeneratePrivateFromPKCS8() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            byte[] encoded = ecKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof ECPrivateKey);
            assertArrayEquals(encoded, privateKey.getEncoded());
        }

        @Test
        @DisplayName("Generate public key from ECPublicKeySpec")
        void testGeneratePublicFromECSpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            ECPublicKey ecPub = (ECPublicKey) ecKeyPair.getPublic();
            ECPublicKeySpec spec = new ECPublicKeySpec(ecPub.getW(), ecPub.getParams());

            PublicKey publicKey = kf.generatePublic(spec);

            assertNotNull(publicKey);
            assertTrue(publicKey instanceof ECPublicKey);

            ECPublicKey generatedKey = (ECPublicKey) publicKey;
            assertEquals(ecPub.getW(), generatedKey.getW());
        }

        @Test
        @DisplayName("Generate private key from ECPrivateKeySpec")
        void testGeneratePrivateFromECSpec() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            ECPrivateKey ecPriv = (ECPrivateKey) ecKeyPair.getPrivate();
            ECPrivateKeySpec spec = new ECPrivateKeySpec(ecPriv.getS(), ecPriv.getParams());

            PrivateKey privateKey = kf.generatePrivate(spec);

            assertNotNull(privateKey);
            assertTrue(privateKey instanceof ECPrivateKey);

            ECPrivateKey generatedKey = (ECPrivateKey) privateKey;
            assertEquals(ecPriv.getS(), generatedKey.getS());
        }

        @Test
        @DisplayName("Get X509EncodedKeySpec from EC public key")
        void testGetX509SpecFromPublic() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            X509EncodedKeySpec spec = kf.getKeySpec(ecKeyPair.getPublic(), X509EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(ecKeyPair.getPublic().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Get ECPublicKeySpec from EC public key")
        void testGetECSpecFromPublic() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            ECPublicKeySpec spec = kf.getKeySpec(ecKeyPair.getPublic(), ECPublicKeySpec.class);

            assertNotNull(spec);
            ECPublicKey ecPub = (ECPublicKey) ecKeyPair.getPublic();
            assertEquals(ecPub.getW(), spec.getW());
        }

        @Test
        @DisplayName("Get PKCS8EncodedKeySpec from EC private key")
        void testGetPKCS8SpecFromPrivate() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            PKCS8EncodedKeySpec spec = kf.getKeySpec(ecKeyPair.getPrivate(), PKCS8EncodedKeySpec.class);

            assertNotNull(spec);
            assertArrayEquals(ecKeyPair.getPrivate().getEncoded(), spec.getEncoded());
        }

        @Test
        @DisplayName("Translate EC key")
        void testTranslateKey() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "Glassless");

            PublicKey translated = (PublicKey) kf.translateKey(ecKeyPair.getPublic());

            assertNotNull(translated);
            assertTrue(translated instanceof ECPublicKey);
            assertArrayEquals(ecKeyPair.getPublic().getEncoded(), translated.getEncoded());
        }
    }
}
