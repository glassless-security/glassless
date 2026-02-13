package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class AlgorithmParametersTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlasslessProvider());
    }

    @Nested
    @DisplayName("EC AlgorithmParameters")
    class ECTests {

        @Test
        @DisplayName("Initialize with ECGenParameterSpec")
        void testInitWithECGenParameterSpec() throws Exception {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "Glassless");
            params.init(new ECGenParameterSpec("secp256r1"));

            ECGenParameterSpec spec = params.getParameterSpec(ECGenParameterSpec.class);
            assertNotNull(spec);
            assertEquals("secp256r1", spec.getName());
        }

        @Test
        @DisplayName("Encode and decode EC parameters")
        void testEncodeDecodeEC() throws Exception {
            AlgorithmParameters params1 = AlgorithmParameters.getInstance("EC", "Glassless");
            params1.init(new ECGenParameterSpec("secp384r1"));

            byte[] encoded = params1.getEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length > 0);

            AlgorithmParameters params2 = AlgorithmParameters.getInstance("EC", "Glassless");
            params2.init(encoded);

            ECGenParameterSpec spec = params2.getParameterSpec(ECGenParameterSpec.class);
            assertEquals("secp384r1", spec.getName());
        }

        @Test
        @DisplayName("EC parameters toString")
        void testECToString() throws Exception {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "Glassless");
            params.init(new ECGenParameterSpec("secp521r1"));

            String str = params.toString();
            assertTrue(str.contains("secp521r1"));
        }
    }

    @Nested
    @DisplayName("DSA AlgorithmParameters")
    class DSATests {

        @Test
        @DisplayName("Initialize with DSAParameterSpec")
        void testInitWithDSAParameterSpec() throws Exception {
            // Generate DSA parameters
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();

            // Get DSA parameters from key
            java.security.interfaces.DSAPublicKey dsaKey =
                (java.security.interfaces.DSAPublicKey) keyPair.getPublic();
            java.security.interfaces.DSAParams dsaParams = dsaKey.getParams();

            DSAParameterSpec spec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

            AlgorithmParameters params = AlgorithmParameters.getInstance("DSA", "Glassless");
            params.init(spec);

            DSAParameterSpec retrieved = params.getParameterSpec(DSAParameterSpec.class);
            assertNotNull(retrieved);
            assertEquals(spec.getP(), retrieved.getP());
            assertEquals(spec.getQ(), retrieved.getQ());
            assertEquals(spec.getG(), retrieved.getG());
        }

        @Test
        @DisplayName("Encode and decode DSA parameters")
        void testEncodeDecodeDSA() throws Exception {
            BigInteger p = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
            BigInteger q = new BigInteger("1461501637330902918203684832716283019655932542929");
            BigInteger g = new BigInteger("2");

            DSAParameterSpec spec = new DSAParameterSpec(p, q, g);

            AlgorithmParameters params1 = AlgorithmParameters.getInstance("DSA", "Glassless");
            params1.init(spec);

            byte[] encoded = params1.getEncoded();
            assertNotNull(encoded);

            AlgorithmParameters params2 = AlgorithmParameters.getInstance("DSA", "Glassless");
            params2.init(encoded);

            DSAParameterSpec retrieved = params2.getParameterSpec(DSAParameterSpec.class);
            assertEquals(p, retrieved.getP());
            assertEquals(q, retrieved.getQ());
            assertEquals(g, retrieved.getG());
        }
    }

    @Nested
    @DisplayName("DH AlgorithmParameters")
    class DHTests {

        @Test
        @DisplayName("Initialize with DHParameterSpec")
        void testInitWithDHParameterSpec() throws Exception {
            BigInteger p = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
            BigInteger g = BigInteger.valueOf(2);

            DHParameterSpec spec = new DHParameterSpec(p, g);

            AlgorithmParameters params = AlgorithmParameters.getInstance("DH", "Glassless");
            params.init(spec);

            DHParameterSpec retrieved = params.getParameterSpec(DHParameterSpec.class);
            assertNotNull(retrieved);
            assertEquals(p, retrieved.getP());
            assertEquals(g, retrieved.getG());
        }

        @Test
        @DisplayName("DH parameters with private value length")
        void testDHWithPrivateValueLength() throws Exception {
            BigInteger p = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
            BigInteger g = BigInteger.valueOf(2);
            int l = 256;

            DHParameterSpec spec = new DHParameterSpec(p, g, l);

            AlgorithmParameters params = AlgorithmParameters.getInstance("DH", "Glassless");
            params.init(spec);

            DHParameterSpec retrieved = params.getParameterSpec(DHParameterSpec.class);
            assertEquals(l, retrieved.getL());
        }
    }

    @Nested
    @DisplayName("AES AlgorithmParameters")
    class AESTests {

        @Test
        @DisplayName("Initialize with IvParameterSpec")
        void testInitWithIvParameterSpec() throws Exception {
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++) iv[i] = (byte) i;

            AlgorithmParameters params = AlgorithmParameters.getInstance("AES", "Glassless");
            params.init(new IvParameterSpec(iv));

            IvParameterSpec retrieved = params.getParameterSpec(IvParameterSpec.class);
            assertNotNull(retrieved);
            assertArrayEquals(iv, retrieved.getIV());
        }

        @Test
        @DisplayName("Encode and decode AES parameters")
        void testEncodeDecodeAES() throws Exception {
            byte[] iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

            AlgorithmParameters params1 = AlgorithmParameters.getInstance("AES", "Glassless");
            params1.init(new IvParameterSpec(iv));

            byte[] encoded = params1.getEncoded();
            assertNotNull(encoded);
            // Should be OCTET STRING: 04 10 <16 bytes>
            assertEquals(18, encoded.length);
            assertEquals(0x04, encoded[0]);
            assertEquals(16, encoded[1]);

            AlgorithmParameters params2 = AlgorithmParameters.getInstance("AES", "Glassless");
            params2.init(encoded);

            IvParameterSpec retrieved = params2.getParameterSpec(IvParameterSpec.class);
            assertArrayEquals(iv, retrieved.getIV());
        }
    }

    @Nested
    @DisplayName("DESede AlgorithmParameters")
    class DESedeTests {

        @Test
        @DisplayName("Initialize with IvParameterSpec")
        void testInitWithIvParameterSpec() throws Exception {
            byte[] iv = new byte[8];
            for (int i = 0; i < 8; i++) iv[i] = (byte) (i + 1);

            AlgorithmParameters params = AlgorithmParameters.getInstance("DESede", "Glassless");
            params.init(new IvParameterSpec(iv));

            IvParameterSpec retrieved = params.getParameterSpec(IvParameterSpec.class);
            assertNotNull(retrieved);
            assertArrayEquals(iv, retrieved.getIV());
        }
    }

    @Nested
    @DisplayName("GCM AlgorithmParameters")
    class GCMTests {

        @Test
        @DisplayName("Initialize with GCMParameterSpec")
        void testInitWithGCMParameterSpec() throws Exception {
            byte[] iv = new byte[12];
            for (int i = 0; i < 12; i++) iv[i] = (byte) i;
            int tagLen = 128;

            AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", "Glassless");
            params.init(new GCMParameterSpec(tagLen, iv));

            GCMParameterSpec retrieved = params.getParameterSpec(GCMParameterSpec.class);
            assertNotNull(retrieved);
            assertArrayEquals(iv, retrieved.getIV());
            assertEquals(tagLen, retrieved.getTLen());
        }

        @Test
        @DisplayName("Encode and decode GCM parameters")
        void testEncodeDecodeGCM() throws Exception {
            byte[] iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
            int tagLen = 96;

            AlgorithmParameters params1 = AlgorithmParameters.getInstance("GCM", "Glassless");
            params1.init(new GCMParameterSpec(tagLen, iv));

            byte[] encoded = params1.getEncoded();
            assertNotNull(encoded);

            AlgorithmParameters params2 = AlgorithmParameters.getInstance("GCM", "Glassless");
            params2.init(encoded);

            GCMParameterSpec retrieved = params2.getParameterSpec(GCMParameterSpec.class);
            assertArrayEquals(iv, retrieved.getIV());
            assertEquals(tagLen, retrieved.getTLen());
        }
    }

    @Nested
    @DisplayName("OAEP AlgorithmParameters")
    class OAEPTests {

        @Test
        @DisplayName("Initialize with OAEPParameterSpec")
        void testInitWithOAEPParameterSpec() throws Exception {
            OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            );

            AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP", "Glassless");
            params.init(spec);

            OAEPParameterSpec retrieved = params.getParameterSpec(OAEPParameterSpec.class);
            assertNotNull(retrieved);
            assertEquals("SHA-256", retrieved.getDigestAlgorithm());
            assertEquals("MGF1", retrieved.getMGFAlgorithm());
        }

        @Test
        @DisplayName("OAEP with SHA-512")
        void testOAEPWithSHA512() throws Exception {
            OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-512",
                "MGF1",
                MGF1ParameterSpec.SHA512,
                PSource.PSpecified.DEFAULT
            );

            AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP", "Glassless");
            params.init(spec);

            OAEPParameterSpec retrieved = params.getParameterSpec(OAEPParameterSpec.class);
            assertEquals("SHA-512", retrieved.getDigestAlgorithm());
        }
    }

    @Nested
    @DisplayName("PSS AlgorithmParameters")
    class PSSTests {

        @Test
        @DisplayName("Initialize with PSSParameterSpec")
        void testInitWithPSSParameterSpec() throws Exception {
            PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
            );

            AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", "Glassless");
            params.init(spec);

            PSSParameterSpec retrieved = params.getParameterSpec(PSSParameterSpec.class);
            assertNotNull(retrieved);
            assertEquals("SHA-256", retrieved.getDigestAlgorithm());
            assertEquals("MGF1", retrieved.getMGFAlgorithm());
            assertEquals(32, retrieved.getSaltLength());
            assertEquals(1, retrieved.getTrailerField());
        }

        @Test
        @DisplayName("Encode and decode PSS parameters")
        void testEncodeDecodePSS() throws Exception {
            PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-384",
                "MGF1",
                MGF1ParameterSpec.SHA384,
                48,
                1
            );

            AlgorithmParameters params1 = AlgorithmParameters.getInstance("RSASSA-PSS", "Glassless");
            params1.init(spec);

            byte[] encoded = params1.getEncoded();
            assertNotNull(encoded);

            AlgorithmParameters params2 = AlgorithmParameters.getInstance("RSASSA-PSS", "Glassless");
            params2.init(encoded);

            PSSParameterSpec retrieved = params2.getParameterSpec(PSSParameterSpec.class);
            assertEquals("SHA-384", retrieved.getDigestAlgorithm());
            assertEquals(48, retrieved.getSaltLength());
        }

        @Test
        @DisplayName("PSS alias works")
        void testPSSAlias() throws Exception {
            AlgorithmParameters params = AlgorithmParameters.getInstance("PSS", "Glassless");
            assertNotNull(params);

            PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
            );
            params.init(spec);

            PSSParameterSpec retrieved = params.getParameterSpec(PSSParameterSpec.class);
            assertEquals("SHA-256", retrieved.getDigestAlgorithm());
        }
    }

    @Nested
    @DisplayName("PBE AlgorithmParameters")
    class PBETests {

        @Test
        @DisplayName("Initialize with PBEParameterSpec")
        void testInitWithPBEParameterSpec() throws Exception {
            byte[] salt = new byte[16];
            for (int i = 0; i < 16; i++) salt[i] = (byte) i;
            int iterationCount = 10000;

            AlgorithmParameters params = AlgorithmParameters.getInstance("PBEWithHmacSHA1AndAES_128", "Glassless");
            params.init(new PBEParameterSpec(salt, iterationCount));

            PBEParameterSpec retrieved = params.getParameterSpec(PBEParameterSpec.class);
            assertNotNull(retrieved);
            assertArrayEquals(salt, retrieved.getSalt());
            assertEquals(iterationCount, retrieved.getIterationCount());
        }

        @Test
        @DisplayName("PBE parameters with IV")
        void testPBEWithIV() throws Exception {
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++) {
                salt[i] = (byte) i;
                iv[i] = (byte) (i + 16);
            }
            int iterationCount = 10000;

            AlgorithmParameters params = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128", "Glassless");
            params.init(new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(iv)));

            PBEParameterSpec retrieved = params.getParameterSpec(PBEParameterSpec.class);
            assertNotNull(retrieved);
            assertArrayEquals(salt, retrieved.getSalt());
            assertEquals(iterationCount, retrieved.getIterationCount());
            assertNotNull(retrieved.getParameterSpec());
            assertTrue(retrieved.getParameterSpec() instanceof IvParameterSpec);
            assertArrayEquals(iv, ((IvParameterSpec) retrieved.getParameterSpec()).getIV());
        }

        @Test
        @DisplayName("Encode and decode PBE parameters")
        void testEncodeDecodePBE() throws Exception {
            byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
            byte[] iv = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
            int iterationCount = 50000;

            AlgorithmParameters params1 = AlgorithmParameters.getInstance("PBEWithHmacSHA512AndAES_256", "Glassless");
            params1.init(new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(iv)));

            byte[] encoded = params1.getEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length > 0);

            AlgorithmParameters params2 = AlgorithmParameters.getInstance("PBEWithHmacSHA512AndAES_256", "Glassless");
            params2.init(encoded);

            PBEParameterSpec retrieved = params2.getParameterSpec(PBEParameterSpec.class);
            assertArrayEquals(salt, retrieved.getSalt());
            assertEquals(iterationCount, retrieved.getIterationCount());
        }

        @Test
        @DisplayName("PBES2 alias works")
        void testPBES2Alias() throws Exception {
            AlgorithmParameters params = AlgorithmParameters.getInstance("PBES2", "Glassless");
            assertNotNull(params);

            byte[] salt = new byte[16];
            params.init(new PBEParameterSpec(salt, 10000));

            PBEParameterSpec retrieved = params.getParameterSpec(PBEParameterSpec.class);
            assertEquals(10000, retrieved.getIterationCount());
        }

        @Test
        @DisplayName("PBE parameters toString")
        void testPBEToString() throws Exception {
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];

            AlgorithmParameters params = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_256", "Glassless");
            params.init(new PBEParameterSpec(salt, 100000, new IvParameterSpec(iv)));

            String str = params.toString();
            assertTrue(str.contains("salt"));
            assertTrue(str.contains("16"));
            assertTrue(str.contains("100000"));
        }
    }
}
