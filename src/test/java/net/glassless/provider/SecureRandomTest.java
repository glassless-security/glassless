package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class SecureRandomTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("SecureRandom Basic Operations")
    class BasicTests {

        @ParameterizedTest(name = "Algorithm: {0}")
        @ValueSource(strings = {"NativePRNG", "DRBG", "SHA1PRNG"})
        void testGetInstance(String algorithm) throws Exception {
            SecureRandom sr = SecureRandom.getInstance(algorithm, "GlaSSLess");
            assertNotNull(sr);
            assertEquals(algorithm, sr.getAlgorithm());
            assertEquals("GlaSSLess", sr.getProvider().getName());
        }

        @ParameterizedTest(name = "Algorithm: {0}")
        @ValueSource(strings = {"NativePRNG", "DRBG", "SHA1PRNG"})
        void testNextBytes(String algorithm) throws Exception {
            SecureRandom sr = SecureRandom.getInstance(algorithm, "GlaSSLess");

            byte[] bytes = new byte[32];
            sr.nextBytes(bytes);

            // Verify bytes were filled (not all zeros)
            boolean hasNonZero = false;
            for (byte b : bytes) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "Random bytes should contain non-zero values");
        }

        @ParameterizedTest(name = "Algorithm: {0}")
        @ValueSource(strings = {"NativePRNG", "DRBG", "SHA1PRNG"})
        void testGenerateSeed(String algorithm) throws Exception {
            SecureRandom sr = SecureRandom.getInstance(algorithm, "GlaSSLess");

            byte[] seed = sr.generateSeed(32);

            assertNotNull(seed);
            assertEquals(32, seed.length);

            // Verify seed has entropy
            boolean hasNonZero = false;
            for (byte b : seed) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "Seed should contain non-zero values");
        }

        @Test
        @DisplayName("Successive calls produce different bytes")
        void testRandomnessQuality() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNG", "GlaSSLess");

            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            sr.nextBytes(bytes1);
            sr.nextBytes(bytes2);

            assertFalse(Arrays.equals(bytes1, bytes2), "Successive random bytes should be different");
        }

        @Test
        @DisplayName("Different instances produce different bytes")
        void testDifferentInstances() throws Exception {
            SecureRandom sr1 = SecureRandom.getInstance("DRBG", "GlaSSLess");
            SecureRandom sr2 = SecureRandom.getInstance("DRBG", "GlaSSLess");

            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            sr1.nextBytes(bytes1);
            sr2.nextBytes(bytes2);

            assertFalse(Arrays.equals(bytes1, bytes2), "Different instances should produce different bytes");
        }
    }

    @Nested
    @DisplayName("SecureRandom Seeding")
    class SeedingTests {

        @Test
        @DisplayName("SetSeed does not throw")
        void testSetSeed() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNG", "GlaSSLess");

            byte[] seed = new byte[32];
            Arrays.fill(seed, (byte) 0x42);

            // Should not throw
            sr.setSeed(seed);

            // Should still produce random bytes
            byte[] bytes = new byte[32];
            sr.nextBytes(bytes);

            boolean hasNonZero = false;
            for (byte b : bytes) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero);
        }

        @Test
        @DisplayName("SetSeed with long value")
        void testSetSeedLong() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("DRBG", "GlaSSLess");

            // Should not throw
            sr.setSeed(12345678L);

            byte[] bytes = new byte[32];
            sr.nextBytes(bytes);
            assertNotNull(bytes);
        }
    }

    @Nested
    @DisplayName("SecureRandom Various Sizes")
    class SizeTests {

        @ParameterizedTest(name = "Size: {0} bytes")
        @ValueSource(ints = {1, 8, 16, 32, 64, 128, 256, 1024, 4096})
        void testVariousSizes(int size) throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNG", "GlaSSLess");

            byte[] bytes = new byte[size];
            sr.nextBytes(bytes);

            assertEquals(size, bytes.length);

            // For sizes > 1, verify some randomness
            if (size > 1) {
                Set<Byte> uniqueBytes = new HashSet<>();
                for (byte b : bytes) {
                    uniqueBytes.add(b);
                }
                // Should have multiple unique byte values for larger sizes
                assertTrue(uniqueBytes.size() > 1, "Random bytes should have variation");
            }
        }

        @Test
        @DisplayName("Zero length array")
        void testZeroLength() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("DRBG", "GlaSSLess");

            byte[] bytes = new byte[0];
            sr.nextBytes(bytes); // Should not throw

            assertEquals(0, bytes.length);
        }

        @Test
        @DisplayName("Generate seed of various sizes")
        void testGenerateSeedSizes() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "GlaSSLess");

            for (int size : new int[]{8, 16, 32, 64}) {
                byte[] seed = sr.generateSeed(size);
                assertEquals(size, seed.length);
            }
        }
    }

    @Nested
    @DisplayName("SecureRandom Aliases")
    class AliasTests {

        @Test
        @DisplayName("NativePRNGBlocking alias works")
        void testNativePRNGBlockingAlias() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNGBlocking", "GlaSSLess");
            assertNotNull(sr);

            byte[] bytes = new byte[16];
            sr.nextBytes(bytes);
        }

        @Test
        @DisplayName("NativePRNGNonBlocking alias works")
        void testNativePRNGNonBlockingAlias() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNGNonBlocking", "GlaSSLess");
            assertNotNull(sr);

            byte[] bytes = new byte[16];
            sr.nextBytes(bytes);
        }
    }

    @Nested
    @DisplayName("SecureRandom Integer Methods")
    class IntegerTests {

        @Test
        @DisplayName("nextInt produces varied results")
        void testNextInt() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNG", "GlaSSLess");

            Set<Integer> values = new HashSet<>();
            for (int i = 0; i < 100; i++) {
                values.add(sr.nextInt());
            }

            // Should have many unique values
            assertTrue(values.size() > 50, "nextInt should produce varied results");
        }

        @Test
        @DisplayName("nextInt with bound")
        void testNextIntBound() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("DRBG", "GlaSSLess");

            int bound = 100;
            for (int i = 0; i < 100; i++) {
                int value = sr.nextInt(bound);
                assertTrue(value >= 0 && value < bound, "Value should be in range [0, " + bound + ")");
            }
        }

        @Test
        @DisplayName("nextLong produces varied results")
        void testNextLong() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "GlaSSLess");

            Set<Long> values = new HashSet<>();
            for (int i = 0; i < 100; i++) {
                values.add(sr.nextLong());
            }

            // Should have many unique values
            assertTrue(values.size() > 50, "nextLong should produce varied results");
        }

        @Test
        @DisplayName("nextDouble produces values in [0, 1)")
        void testNextDouble() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("NativePRNG", "GlaSSLess");

            for (int i = 0; i < 100; i++) {
                double value = sr.nextDouble();
                assertTrue(value >= 0.0 && value < 1.0, "nextDouble should be in [0, 1)");
            }
        }

        @Test
        @DisplayName("nextBoolean produces both true and false")
        void testNextBoolean() throws Exception {
            SecureRandom sr = SecureRandom.getInstance("DRBG", "GlaSSLess");

            boolean seenTrue = false;
            boolean seenFalse = false;

            for (int i = 0; i < 100 && !(seenTrue && seenFalse); i++) {
                if (sr.nextBoolean()) {
                    seenTrue = true;
                } else {
                    seenFalse = true;
                }
            }

            assertTrue(seenTrue && seenFalse, "nextBoolean should produce both true and false");
        }
    }
}
