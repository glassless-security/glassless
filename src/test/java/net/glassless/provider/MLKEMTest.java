package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KEM;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Tests for ML-KEM (FIPS 203) Key Encapsulation Mechanism.
 * Tests will be skipped if OpenSSL 3.5+ is not available.
 */
public class MLKEMTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    private static void assumeMLKEMAvailable() {
        assumeTrue(OpenSSLCrypto.isKEMAvailable(), "KEM operations require OpenSSL 3.2+");
        assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem768"),
            "ML-KEM requires OpenSSL 3.5+");
    }

    @Nested
    @DisplayName("ML-KEM-512 Tests")
    class MLKEM512Tests {

        @Test
        @DisplayName("Generate ML-KEM-512 key pair")
        void testGenerateKeyPair() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem512"),
                "ML-KEM-512 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-512", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());

            assertEquals("ML-KEM-512", kp.getPublic().getAlgorithm());
            assertEquals("ML-KEM-512", kp.getPrivate().getAlgorithm());
            assertEquals("X.509", kp.getPublic().getFormat());
            assertEquals("PKCS#8", kp.getPrivate().getFormat());
        }

        @Test
        @DisplayName("ML-KEM-512 encapsulate and decapsulate")
        void testEncapsulateDecapsulate() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem512"),
                "ML-KEM-512 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-512", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            KEM kem = KEM.getInstance("ML-KEM-512", "GlaSSLess");

            // Encapsulate
            KEM.Encapsulator encapsulator = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();

            assertNotNull(encapsulated);
            assertNotNull(encapsulated.key());
            assertNotNull(encapsulated.encapsulation());

            // Decapsulate
            KEM.Decapsulator decapsulator = kem.newDecapsulator(kp.getPrivate());
            javax.crypto.SecretKey decapsulatedKey = decapsulator.decapsulate(encapsulated.encapsulation());

            assertNotNull(decapsulatedKey);
            assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
        }
    }

    @Nested
    @DisplayName("ML-KEM-768 Tests")
    class MLKEM768Tests {

        @Test
        @DisplayName("Generate ML-KEM-768 key pair")
        void testGenerateKeyPair() throws Exception {
            assumeMLKEMAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("ML-KEM-768", kp.getPublic().getAlgorithm());
            assertEquals("ML-KEM-768", kp.getPrivate().getAlgorithm());
        }

        @Test
        @DisplayName("ML-KEM-768 encapsulate and decapsulate")
        void testEncapsulateDecapsulate() throws Exception {
            assumeMLKEMAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            KEM kem = KEM.getInstance("ML-KEM-768", "GlaSSLess");

            // Encapsulate
            KEM.Encapsulator encapsulator = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();

            assertNotNull(encapsulated);
            assertEquals(32, encapsulated.key().getEncoded().length);  // 256-bit shared secret

            // Decapsulate
            KEM.Decapsulator decapsulator = kem.newDecapsulator(kp.getPrivate());
            javax.crypto.SecretKey decapsulatedKey = decapsulator.decapsulate(encapsulated.encapsulation());

            assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
        }

        @Test
        @DisplayName("Generic ML-KEM with NamedParameterSpec")
        void testGenericMLKEMWithSpec() throws Exception {
            assumeMLKEMAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "GlaSSLess");
            kpg.initialize(new NamedParameterSpec("ML-KEM-768"));
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("ML-KEM-768", kp.getPublic().getAlgorithm());
        }
    }

    @Nested
    @DisplayName("ML-KEM-1024 Tests")
    class MLKEM1024Tests {

        @Test
        @DisplayName("Generate ML-KEM-1024 key pair")
        void testGenerateKeyPair() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem1024"),
                "ML-KEM-1024 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-1024", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            assertNotNull(kp);
            assertEquals("ML-KEM-1024", kp.getPublic().getAlgorithm());
            assertEquals("ML-KEM-1024", kp.getPrivate().getAlgorithm());
        }

        @Test
        @DisplayName("ML-KEM-1024 encapsulate and decapsulate")
        void testEncapsulateDecapsulate() throws Exception {
            assumeTrue(OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem1024"),
                "ML-KEM-1024 requires OpenSSL 3.5+");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-1024", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            KEM kem = KEM.getInstance("ML-KEM-1024", "GlaSSLess");

            KEM.Encapsulator encapsulator = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();

            KEM.Decapsulator decapsulator = kem.newDecapsulator(kp.getPrivate());
            javax.crypto.SecretKey decapsulatedKey = decapsulator.decapsulate(encapsulated.encapsulation());

            assertArrayEquals(encapsulated.key().getEncoded(), decapsulatedKey.getEncoded());
        }
    }

    @Nested
    @DisplayName("ML-KEM KeyFactory Tests")
    class MLKEMKeyFactoryTests {

        @Test
        @DisplayName("Reconstruct ML-KEM keys from encoded")
        void testReconstructKeys() throws Exception {
            assumeMLKEMAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "GlaSSLess");
            KeyPair original = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("ML-KEM", "GlaSSLess");

            // Reconstruct public key
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(original.getPublic().getEncoded());
            PublicKey reconstructedPub = kf.generatePublic(pubSpec);
            assertArrayEquals(original.getPublic().getEncoded(), reconstructedPub.getEncoded());

            // Reconstruct private key
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(original.getPrivate().getEncoded());
            java.security.PrivateKey reconstructedPriv = kf.generatePrivate(privSpec);
            assertArrayEquals(original.getPrivate().getEncoded(), reconstructedPriv.getEncoded());

            // Use reconstructed keys for KEM
            KEM kem = KEM.getInstance("ML-KEM-768", "GlaSSLess");
            KEM.Encapsulator enc = kem.newEncapsulator(reconstructedPub);
            KEM.Encapsulated encapsulated = enc.encapsulate();

            KEM.Decapsulator dec = kem.newDecapsulator(reconstructedPriv);
            javax.crypto.SecretKey decapsulated = dec.decapsulate(encapsulated.encapsulation());

            assertArrayEquals(encapsulated.key().getEncoded(), decapsulated.getEncoded());
        }
    }

    @Nested
    @DisplayName("ML-KEM Secret Key Usage Tests")
    class MLKEMSecretKeyUsageTests {

        @Test
        @DisplayName("Use ML-KEM derived key with algorithm name")
        void testDerivedKeyWithAlgorithm() throws Exception {
            assumeMLKEMAvailable();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "GlaSSLess");
            KeyPair kp = kpg.generateKeyPair();

            KEM kem = KEM.getInstance("ML-KEM-768", "GlaSSLess");
            KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());

            // Request AES key
            KEM.Encapsulated encapsulated = enc.encapsulate(0, 16, "AES");

            assertEquals("AES", encapsulated.key().getAlgorithm());
            assertEquals(16, encapsulated.key().getEncoded().length);

            KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
            javax.crypto.SecretKey decapsulated = dec.decapsulate(encapsulated.encapsulation(), 0, 16, "AES");

            assertEquals("AES", decapsulated.getAlgorithm());
            assertArrayEquals(encapsulated.key().getEncoded(), decapsulated.getEncoded());
        }
    }
}
