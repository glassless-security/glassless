package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.DSAGenParameterSpec;
import java.security.spec.DSAParameterSpec;

import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class AlgorithmParameterGeneratorTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("DSA AlgorithmParameterGenerator")
    class DSATests {

        @Test
        @DisplayName("Generate DSA parameters with default size")
        void testGenerateDSAParametersDefault() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "GlaSSLess");
            assertNotNull(gen);

            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            assertNotNull(params);
            assertEquals("DSA", params.getAlgorithm());

            DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);
            assertNotNull(spec);
            assertNotNull(spec.getP());
            assertNotNull(spec.getQ());
            assertNotNull(spec.getG());

            // Verify sizes
            assertEquals(2048, spec.getP().bitLength());
            assertTrue(spec.getQ().bitLength() >= 224 && spec.getQ().bitLength() <= 256);
        }

        @Test
        @DisplayName("Generate DSA parameters with DSAGenParameterSpec")
        void testGenerateDSAParametersWithSpec() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "GlaSSLess");

            DSAGenParameterSpec genSpec = new DSAGenParameterSpec(2048, 256);
            gen.init(genSpec);

            AlgorithmParameters params = gen.generateParameters();
            assertNotNull(params);

            DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);
            assertEquals(2048, spec.getP().bitLength());
            assertEquals(256, spec.getQ().bitLength());
        }

        @Test
        @DisplayName("Generated DSA parameters can be used for key generation")
        void testDSAParametersForKeyGen() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "GlaSSLess");
            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            DSAParameterSpec dsaSpec = params.getParameterSpec(DSAParameterSpec.class);

            // Use parameters for key generation
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(dsaSpec);

            KeyPair keyPair = kpg.generateKeyPair();
            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());
        }

        @Test
        @DisplayName("DSA parameters have valid mathematical properties")
        void testDSAParameterProperties() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "GlaSSLess");
            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);

            BigInteger p = spec.getP();
            BigInteger q = spec.getQ();
            BigInteger g = spec.getG();

            // q should divide (p-1)
            BigInteger pMinus1 = p.subtract(BigInteger.ONE);
            assertEquals(BigInteger.ZERO, pMinus1.mod(q), "q should divide (p-1)");

            // g should be > 1
            assertTrue(g.compareTo(BigInteger.ONE) > 0, "g should be greater than 1");

            // g should be < p
            assertTrue(g.compareTo(p) < 0, "g should be less than p");

            // g^q mod p should be 1
            BigInteger gToQ = g.modPow(q, p);
            assertEquals(BigInteger.ONE, gToQ, "g^q mod p should be 1");
        }
    }

    @Nested
    @DisplayName("DH AlgorithmParameterGenerator")
    class DHTests {

        @Test
        @DisplayName("Generate DH parameters with default size")
        void testGenerateDHParametersDefault() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "GlaSSLess");
            assertNotNull(gen);

            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            assertNotNull(params);
            assertEquals("DH", params.getAlgorithm());

            DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
            assertNotNull(spec);
            assertNotNull(spec.getP());
            assertNotNull(spec.getG());

            // Verify prime size
            assertEquals(2048, spec.getP().bitLength());
        }

        @Test
        @DisplayName("Generate DH parameters with DHGenParameterSpec")
        void testGenerateDHParametersWithSpec() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "GlaSSLess");

            DHGenParameterSpec genSpec = new DHGenParameterSpec(2048, 256);
            gen.init(genSpec);

            AlgorithmParameters params = gen.generateParameters();
            assertNotNull(params);

            DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
            assertEquals(2048, spec.getP().bitLength());
            assertEquals(256, spec.getL());
        }

        @Test
        @DisplayName("Generated DH parameters can be used for key generation")
        void testDHParametersForKeyGen() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "GlaSSLess");
            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            // Use parameters for key generation
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);

            KeyPair keyPair = kpg.generateKeyPair();
            assertNotNull(keyPair);
            assertNotNull(keyPair.getPublic());
            assertNotNull(keyPair.getPrivate());
        }

        @Test
        @DisplayName("DiffieHellman alias works")
        void testDiffieHellmanAlias() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DiffieHellman", "GlaSSLess");
            assertNotNull(gen);

            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            assertNotNull(params);
        }

        @Test
        @DisplayName("DH parameters have valid generator")
        void testDHParameterProperties() throws Exception {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "GlaSSLess");
            gen.init(2048);

            AlgorithmParameters params = gen.generateParameters();
            DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);

            BigInteger p = spec.getP();
            BigInteger g = spec.getG();

            // g should be >= 2
            assertTrue(g.compareTo(BigInteger.TWO) >= 0, "g should be >= 2");

            // g should be < p
            assertTrue(g.compareTo(p) < 0, "g should be less than p");

            // p should be prime (probabilistic check)
            assertTrue(p.isProbablePrime(20), "p should be probably prime");
        }
    }
}
